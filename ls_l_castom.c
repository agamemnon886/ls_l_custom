#include <sys/sysmacros.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

//-----------------------------------------------------------------------------
// Get file user/group by UID/GID
//-----------------------------------------------------------------------------
int get_ownership_string(
	const unsigned int uid,
	const unsigned int gid,
	char ** const ownership
)
{
	struct passwd pwd;
	struct passwd *pwd_result = NULL;
	struct group gr;
	struct group *gr_result = NULL;
	char *buf = NULL;
	size_t bufsize = 0;
	int ret = -1;
	size_t ownership_size = 0;

	if(ownership == NULL) {
		fprintf(stderr, "Invalid argument\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Get username by UID
	//-------------------------------------------------------------------------
	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) {          /* Value was indeterminate */
		bufsize = 16384;        /* Should be more than enough */
	}

	buf = (char *)calloc(sizeof(char), bufsize);
	if (buf == NULL) {
		perror("malloc");
		goto exit;
	}

	memset(&pwd, 0, sizeof(pwd));

	getpwuid_r(uid, &pwd, buf, bufsize, &pwd_result);
	if(pwd_result == NULL) {
		fprintf(stderr, "getpwnam_r failed\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Get group name by GID
	//-------------------------------------------------------------------------
	memset(&gr, 0, sizeof(gr));

	getgrgid_r(gid, &gr, buf, bufsize, &gr_result);
	if(gr_result == NULL) {
		fprintf(stderr, "getpwnam_r failed\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Size of result string is (size of user name) + (size of group name) +
	// + (one space) + (end of string)
	//-------------------------------------------------------------------------
	ownership_size = strlen(pwd.pw_name) + strlen(gr.gr_name) + 1 + 1;

	*ownership = (char *)malloc(ownership_size);
	if (*ownership == NULL) {
		perror("calloc");
		goto exit;
	}

	snprintf(*ownership, ownership_size, "%s %s", pwd.pw_name, gr.gr_name);

	free(buf);
	buf = NULL;

	ret = 0;

exit:

	if(buf != NULL) {
		free(buf);
		buf = NULL;
	}

	return ret;
}

//-----------------------------------------------------------------------------
// Get file permissions string
//-----------------------------------------------------------------------------
int get_permissions_string(
	const unsigned int mode,
	char * const access,
	const size_t access_size)
{
	char r = 'r';
	char w = 'w';
	char x = 'x';
	char forbidden = '-';
	int ret = -1;

	if(
		(access == NULL) ||
		(access_size < 10)
	) {
		fprintf(stderr, "Invalid argument\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Get user permissions
	//-------------------------------------------------------------------------
	if(mode & S_IRWXU) {
		mode & S_IRUSR ? access[0] = r : (access[0] = forbidden);
		mode & S_IWUSR ? access[1] = w : (access[1] = forbidden);
		mode & S_IXUSR ? access[2] = x : (access[2] = forbidden);
	} else {
		strcpy(access, "---");
	}

	//-------------------------------------------------------------------------
	// Get group permissions
	//-------------------------------------------------------------------------
	if(mode & S_IRWXG) {
		mode & S_IRGRP ? (access[3] = r) : (access[3] = forbidden);
		mode & S_IWGRP ? (access[4] = w) : (access[4] = forbidden);
		mode & S_IXGRP ? (access[5] = x) : (access[5] = forbidden);
	} else {
		strcpy(access + 3, "---");
	}

	//-------------------------------------------------------------------------
	// Get other permissions
	//-------------------------------------------------------------------------
	if(mode & S_IRWXO) {
		mode & S_IROTH ? (access[6] = r) : (access[6] = forbidden);
		mode & S_IWOTH ? (access[7] = w) : (access[7] = forbidden);
		mode & S_IXOTH ? (access[8] = x) : (access[8] = forbidden);
	} else {
		strcpy(access + 6, "---");
	}

	access[9] = '\0';

	ret = 0;

exit:

	return ret;
}

//-----------------------------------------------------------------------------
// Print file stat info
//-----------------------------------------------------------------------------
int print_file_info(const char * const root, const char * const path)
{
	struct stat s_stat;
	struct tm tm_date;
	int ret = -1;
	char file_type = '-';
	char access[10] = { '\0' };
	char str_date[100] = { '\0' };
	char buf[PATH_MAX] = { '\0' };
	char *ownership = NULL;
	char full_path[PATH_MAX] = { '\0' };

	if(
		(root == NULL) ||
		(path == NULL)
	) {
		fprintf(stderr, "Invalid argument\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Obtain file type
	//-------------------------------------------------------------------------
	snprintf(full_path, PATH_MAX, "%s%s", root, path);

	memset(&s_stat, 0, sizeof(s_stat));

	ret = lstat(full_path, &s_stat);
	if(ret < 0) {
		perror("stat");
		goto exit;
	}

	switch (s_stat.st_mode & S_IFMT) {
		case S_IFBLK:
			file_type = 'b';
			break;

		case S_IFCHR:
			file_type = 'c';
			break;

		case S_IFDIR:
			file_type = 'd';
			break;

		case S_IFIFO:
			file_type = 'p';
			break;

		case S_IFLNK:
			file_type = 'l';
			break;

		case S_IFREG:
			file_type = '-';
			break;

		case S_IFSOCK:
			file_type = 's';
			break;

		default:
			 printf("unknown?\n");
		break;
	}

	//-------------------------------------------------------------------------
	// Get file permissions
	//-------------------------------------------------------------------------
	ret = get_permissions_string(s_stat.st_mode, access, 10);
	if(ret < 0) {
		fprintf(stderr, "get_access_string returned error\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Get file owner's user and group
	//-------------------------------------------------------------------------
	ret = get_ownership_string(s_stat.st_uid, s_stat.st_gid, &ownership);
	if(ret < 0) {
		fprintf(stderr, "get_ownership_string failed\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Get modification date
	//-------------------------------------------------------------------------
	memset(&tm_date, 0, sizeof(struct tm));
	if(localtime_r(&s_stat.st_mtime, &tm_date) == NULL) {
		perror("localtime_r");
		goto exit;
	}

	strftime(str_date, sizeof(str_date), "%b %e %R", &tm_date);

	//-------------------------------------------------------------------------
	// Print result string
	//-------------------------------------------------------------------------
	printf("%c%s %3lu %s ",
		file_type, access, s_stat.st_nlink, ownership);

	if(
		(file_type == 'c') ||
		(file_type == 'b')
	) {
		printf("%d,%d ", major(s_stat.st_rdev), minor(s_stat.st_rdev));
	} else {
		printf("%ld ", s_stat.st_size);
	}

	printf("%s %s", str_date, path);

	if(
		(file_type == 'l') &&
		(readlink(full_path, buf, PATH_MAX) != -1)
	) {
		printf(" -> %s", buf);
	}

	printf("\n");
	fflush(stdout);

	//-------------------------------------------------------------------------
	// Free memory
	//-------------------------------------------------------------------------
	free(ownership);
	ownership = NULL;

	ret = 0;

exit:

	if(ownership != NULL) {
		free(ownership);
		ownership = NULL;
	}

	return ret;
}

//-----------------------------------------------------------------------------
// Discard "." and ".." directories
//-----------------------------------------------------------------------------
int sel(const struct dirent *d)
{
	if(
		(strcmp(d->d_name, ".") != 0) &&
		(strcmp(d->d_name, "..") != 0)
	) {
		return 1;
	}

	return 0;
}

//-----------------------------------------------------------------------------
// Process directory
//-----------------------------------------------------------------------------
int process_dir(const char * const dir){
	struct dirent **namelist = NULL;
	int i = 0;
	int n = 0;
	int ret = -1;

	if(dir == NULL) {
		fprintf(stderr, "Invalid argument\n");
		goto exit;
	}

	//-------------------------------------------------------------------------
	// Scan directory and sort it in alphabet order
	//-------------------------------------------------------------------------
	n = scandir(dir, &namelist, sel, alphasort);
	if (n < 0) {
		perror("scandir");
		goto exit;
	}

	printf("%s:\n", dir);

	for (i = 0; i < n; i++) {
		//---------------------------------------------------------------------
		// Print file stat info
		//---------------------------------------------------------------------
		print_file_info(dir, namelist[i]->d_name);

		free(namelist[i]);
		namelist[i] = NULL;
	}

	free(namelist);
	namelist = NULL;

	ret = 0;

exit:

	if(namelist != NULL) {
		free(namelist);
		namelist = NULL;
	}

	return ret;
}

//-----------------------------------------------------------------------------
// Is it directory? (1 - yes, 0 - no)
//-----------------------------------------------------------------------------
int is_dir(const char * const path) {
	struct stat s_stat;
	int ret = 0;

	if(path == NULL) {
		goto exit;
	}

	memset(&s_stat, 0, sizeof(s_stat));

	if(stat(path, &s_stat) < 0) {
		goto exit;
	}

	if(S_ISDIR(s_stat.st_mode)) {
		ret = 1;
	}

exit:

	return ret;
}

int main(int argc, char **argv) {
	int ret = EXIT_SUCCESS;

	//-------------------------------------------------------------------------
	// For each argument
	//-------------------------------------------------------------------------
	for(int i = 1; i < argc; i++) {
		//---------------------------------------------------------------------
		// Is it directory?
		//---------------------------------------------------------------------
		if(is_dir(argv[i])) {
			if(process_dir(argv[i]) < 0) {
				ret = EXIT_FAILURE;
			}
		} else {
			if(print_file_info("", argv[i]) < 0) {
				ret = EXIT_FAILURE;
			}
		}

		printf("\n");
		fflush(stdout);
	}

	return ret;
}
