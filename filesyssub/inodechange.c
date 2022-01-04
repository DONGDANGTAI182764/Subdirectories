#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

struct thread {
	...
#ifdef VM
	...
	// directory 표시
	struct dir *cur_dir;
#endif
	...
};

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t unused[125];               /* Not used. */

	uint32_t is_dir;					// 디렉토리 구분
};

// inode가 directory인지 판단
bool inode_is_dir(const struct inode* inode) {
    bool result;

    // inode_disk 자료구조를 메모리에 할당
    struct inode_disk *disk_inode = calloc (1, sizeof *disk_inode);

    // in-memory inode의on-disk inode를읽어inode_disk에저장
    disk_read(filesys_disk, cluster_to_sector(inode->sector), disk_inode);

    // on-disk inode의is_dir을result에저장하여반환
    result = disk_inode->is_dir;
    free(disk_inode);

    return result;
}

// 현재 디렉토리의 위치 변경
bool sys_chdir(const char *path_name) {
    if (path_name == NULL) {
        return false;
	}

    // name의 파일 경로 를 cp_name에 복사
    char *cp_name = (char *)malloc(strlen(path_name) + 1);
    strlcpy(cp_name, path_name, strlen(path_name) + 1);

    struct dir *chdir = NULL;

    if (cp_name[0] == '/') {	// 절대 경로로 디렉토리 되어 있다면
        chdir = dir_open_root();
    }
    else {						// 상대 경로로 디렉토리 되어 있다면
        chdir = dir_reopen(thread_current()->cur_dir);
	}

    // dir경로를 분석하여 디렉터리를 반환
    char *token, *savePtr;
    token = strtok_r(cp_name, "/", &savePtr);

    struct inode *inode = NULL;
    while (token != NULL) {
        // dir에서 token이름의 파일을 검색하여 inode의 정보를 저장
        if (!dir_lookup(chdir, token, &inode)) {
            dir_close(chdir);
            return false;
        }

        // inode가 파일일 경우 NULL 반환
        if (!inode_is_dir(inode)) {
            dir_close(chdir);
            return false;
        }

        // dir의 디렉터리 정보를 메모리에서 해지
        dir_close(chdir);
        
        // inode의 디렉터리 정보를 dir에저장
        chdir = dir_open(inode);

        // token에검색할경로이름저장
        token = strtok_r(NULL, "/", &savePtr);
    }
    // 스레드의현재작업디렉터리를변경
    dir_close(thread_current()->cur_dir);
    thread_current()->cur_dir = chdir;
    free(cp_name);
    return true;
}

/ directory 생성
bool sys_mkdir(const char *dir) {
    lock_acquire(&file_rw_lock);
    bool new_dir = filesys_create_dir(dir);
    lock_release(&file_rw_lock);
    return new_dir;
}

bool filesys_create_dir(const char* name) {

    bool success = false;

    // name의 파일경로를 cp_name에복사
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    // name 경로분석
    char* file_name = (char *)malloc(strlen(name) + 1);
    struct dir* dir = parse_path(cp_name, file_name);


    // bitmap에서 inode sector 번호 할당
    cluster_t inode_cluster = fat_create_chain(0);
    struct inode *sub_dir_inode;
    struct dir *sub_dir = NULL;


    /* 할당 받은 sector에 file_name의 디렉터리 생성
	   디렉터리 엔트리에 file_name의 엔트리 추가
       디렉터리 엔트리에 ‘.’, ‘..’ 파일의 엔트리 추가 */
    success = (		// ".", ".." 추가
                dir != NULL
            	&& dir_create(inode_cluster, 16)
            	&& dir_add(dir, file_name, inode_cluster)
            	&& dir_lookup(dir, file_name, &sub_dir_inode)
            	&& dir_add(sub_dir = dir_open(sub_dir_inode), ".", inode_cluster)
            	&& dir_add(sub_dir, "..", inode_get_inumber(dir_get_inode(dir))));


    if (!success && inode_cluster != 0) {
        fat_remove_chain(inode_cluster, 0);
	}

    dir_close(sub_dir);
    dir_close(dir);

    free(cp_name);
    free(file_name);
    return success;
}


// 경로 분석 함수 구현
struct dir *parse_path(char *path_name, char *file_name) {  // file_name: path_name을 분석하여 파일, 디렉터리의 이름을 포인팅
    struct dir *dir = NULL;
    if (path_name == NULL || file_name == NULL)
        return NULL;
    if (strlen(path_name) == 0)
        return NULL;

    // path_name의 절대/상대 경로에 따른 디렉터리 정보 저장
    if(path_name[0] == '/') {
        dir = dir_open_root();
    }
    else {
        dir = dir_reopen(thread_current()->cur_dir);
	}

    char *token, *nextToken, *savePtr;
    token = strtok_r(path_name, "/", &savePtr);
    nextToken = strtok_r(NULL, "/", &savePtr);

    // "/"를 open하려는 케이스
    if(token == NULL) {
        token = (char*)malloc(2);
        strlcpy(token, ".", 2);
    }

    struct inode *inode;
    while (token != NULL && nextToken != NULL) {
        // dir에서 token이름의 파일을 검색하여 inode의 정보를 저장
        if (!dir_lookup(dir, token, &inode)) {
            dir_close(dir);
            return NULL;
        }

        if(inode->data.is_link) {   // 링크 파일인 경우

            char* new_path = (char*)malloc(sizeof(strlen(inode->data.link_name)) + 1);
            strlcpy(new_path, inode->data.link_name, strlen(inode->data.link_name) + 1);

            strlcpy(path_name, new_path, strlen(new_path) + 1);
            free(new_path);
 
            strlcat(path_name, "/", strlen(path_name) + 2);
            strlcat(path_name, nextToken, strlen(path_name) + strlen(nextToken) + 1);
            strlcat(path_name, savePtr, strlen(path_name) + strlen(savePtr) + 1);

            dir_close(dir);

            // 파싱된 경로로 다시 시작한다
            if(path_name[0] == '/') {
                dir = dir_open_root();
            }
            else {
                dir = dir_reopen(thread_current()->cur_dir);
            }


            token = strtok_r(path_name, "/", &savePtr);
            nextToken = strtok_r(NULL, "/", &savePtr);

            continue;
        }
        
        // inode가 파일일 경우 NULL 반환
        if(!inode_is_dir(inode)) {
            dir_close(dir);
            inode_close(inode);
            return NULL;
        }
        // dir의 디렉터리 정보를 메모리에서 해지
        dir_close(dir);

        // inode의 디렉터리 정보를 dir에 저장
        dir = dir_open(inode);

        // token에 검색할 경로이름 저장
        token = nextToken;
        nextToken = strtok_r(NULL, "/", &savePtr);
    }
    // token의 파일이름을 file_name에 저장
    strlcpy (file_name, token, strlen(token) + 1);

    // dir정보반환
    return dir;
}

bool inode_create (disk_sector_t sector, off_t length, uint32_t is_dir) {

	// for filesystem
	#ifdef EFILESYS

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;

        // directory 여부 추가
        disk_inode->is_dir = is_dir;
		
		// inode의 파일 정보를 저장할 cluster
		cluster_t cluster = fat_create_chain(0);

		if(cluster) {
            // inode disk 정보 기록
			disk_inode->start = cluster;
			disk_write (filesys_disk, cluster_to_sector(sector), disk_inode);

			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

                // inode file 공간 할당
				disk_write (filesys_disk, cluster_to_sector(disk_inode->start), zeros);

				for (i = 1; i < sectors; i++){
					cluster_t tmp = cluster_to_sector(fat_create_chain(cluster));
					disk_write (filesys_disk, tmp, zeros);
				}
			}
			success = true;
		}
		free (disk_inode);
	}
	return success;

	#else
	...
	#endif
}

bool dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), 1);
}

bool filesys_create (const char *name, off_t initial_size) {
			...
			&& inode_create (inode_sector, initial_size, 0)
			...
}

void free_map_create (void) {
	/* Create inode. */
	if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map), 0))
		PANIC ("free map creation failed");
	...
}

void thread_init (void) {
	...
	#ifdef EFILESYS
    initial_thread->cur_dir = NULL;
    #endif
}

void filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
    // 루트디렉토리 설정
    thread_current()->cur_dir = dir_open_root();  // dir_open_root(): root 디렉터리 정보 반환
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

tid_t thread_create (const char *name, int priority,
	...
	// 자식 스레드의 작업 디렉터리를 부모 스레드의 작업 디렉터리로 디렉터리 다시 오픈하여 설정
	#ifdef EFILESYS
    if(thread_current()->cur_dir != NULL) {
        t->cur_dir = dir_reopen(thread_current()->cur_dir); 
    }
    #endif
	...
}

void process_exit (void) {
	...
	#ifdef EFILESYS
    dir_close(thread_current()->cur_dir); // 스레드의 현재 작업 디렉터리의 정보 메모리에서 해지
    #endif
}

struct inode *inode_open (disk_sector_t sector) {
	...
	disk_read (filesys_disk, cluster_to_sector(inode->sector), &inode->data);
	return inode;
}

bool filesys_create (const char *name, off_t initial_size) {
    bool success = false;
#ifdef EFILESYS

    // name의 파일경로를 cp_name에 복사
    char *cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    // cp_name의 경로분석
    char *file_name = (char *)malloc(strlen(name) + 1);
    struct dir *dir = parse_path(cp_name, file_name);

    cluster_t inode_cluster = fat_create_chain(0);

    success = (dir != NULL
               // 파일의 inode를 생성하고 디렉토리에 추가한다
               && inode_create(inode_cluster, initial_size, 0)
               && dir_add(dir, file_name, inode_cluster));

    if (!success && inode_cluster != 0) {
        fat_remove_chain(inode_cluster, 0);
    }

    dir_close(dir);
    free(cp_name);
    free(file_name);
    return success;

#else
	disk_sector_t inode_sector = 0;
	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, 0)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
	dir_close (dir);

	return success;

#endif
}

struct file *filesys_open (const char *name) {
    #ifdef EFILESYS

    // name의 파일경로를 cp_name에 복사
    char* cp_name = (char *)malloc(strlen(name) + 1);
    char* file_name = (char *)malloc(strlen(name) + 1);

    struct dir* dir = NULL;
    struct inode *inode = NULL;

    while(true) {
        strlcpy(cp_name, name, strlen(name) + 1);
        // cp_name의경로분석
        dir = parse_path(cp_name, file_name);

        if (dir != NULL) {
            dir_lookup(dir, file_name, &inode);
            if(inode && inode->data.is_link) {   // 파일이 존재하고, 링크 파일인 경우
                dir_close(dir);
                name = inode->data.link_name;
                continue;
            }
        }
        free(cp_name);
        free(file_name);
        dir_close(dir);
        break;
    }
    return file_open(inode);

    #else

	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);

    #endif
}

bool filesys_remove (const char *name) {
    #ifdef EFILESYS

    // name의 파일경로를 cp_name에 복사
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    // cp_name의 경로분석
    char* file_name = (char *)malloc(strlen(name) + 1);
    struct dir* dir = parse_path(cp_name, file_name);

    struct inode *inode = NULL;
    bool success = false;

    if (dir != NULL) {
        dir_lookup(dir, file_name, &inode);

        if(inode_is_dir(inode)) {   // 디렉토리인 경우
            struct dir* cur_dir = dir_open(inode);
            char* tmp = (char *)malloc(NAME_MAX + 1);
            dir_seek(cur_dir, 2 * sizeof(struct dir_entry));

            if(!dir_readdir(cur_dir, tmp)) {   // 디렉토리가 비었다
                // 현재 디렉토리가 아니면 지우게 한다
                if(inode_get_inumber(dir_get_inode(thread_current()->cur_dir)) != inode_get_inumber(dir_get_inode(cur_dir)))
                    success = dir_remove(dir, file_name);
            }

            else {   // 디렉토리가 비지 않았다.
                // 찾은 디렉토리에서 지운다
                success = dir_remove(cur_dir, file_name);
            }
            
            dir_close(cur_dir);
            free(tmp);
        }
        else {   // 파일인 경우
            inode_close(inode);
            success = dir_remove(dir, file_name);
        }
    }

    dir_close(dir);
    free(cp_name);
    free(file_name);

    return success;

    #else

	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;

    #endif
}

// directory 내 파일 존재 여부 확인
bool sys_readdir(int fd, char *name) {
    if (name == NULL) {
        return false;
	}

    // fd리스트에서 fd에 대한 file정보 얻어옴
	struct file *target = find_file_by_fd(fd);
    if (target == NULL) {
        return false;
	}

    // fd의 file->inode가 디렉터리인지 검사
    if (!inode_is_dir(file_get_inode(target))) {
        return false;
	}

    // p_file을 dir자료구조로 포인팅
    struct dir *p_file = target;
    if (p_file->pos == 0) {
        dir_seek(p_file, 2 * sizeof(struct dir_entry));		// ".", ".." 제외
	}

    // 디렉터리의 엔트리에서 ".", ".." 이름을 제외한 파일이름을 name에 저장
    bool result = dir_readdir(p_file, name);

    return result;
}
 
// 디렉토리 포지션 변경
void dir_seek (struct dir *dir, off_t new_pos) {
	ASSERT (dir != NULL);
	ASSERT (new_pos >= 0);
	dir->pos = new_pos;
}

/ ../include/filesys/directory.h

...
/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};
...

// file의 directory 여부 판단
bool is_dir(int fd) {
	struct file *target = find_file_by_fd(fd);

    if (target == NULL) {
        return false;
	}

    return inode_is_dir(file_get_inode(target));
}

// file의 inode가 기록된 sector 찾기
struct cluster_t *sys_inumber(int fd) {
	struct file *target = find_file_by_fd(fd);

    if (target == NULL) {
        return false;
	}

    return inode_get_inumber(file_get_inode(target));
}

/* Formats the file system. */
static void do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();

    // '.' '..' 파일 추가
    if (!dir_create(ROOT_DIR_SECTOR, 16)) {
        PANIC("root directory creation failed");
    }
        
    struct dir* root_dir = dir_open_root();
    dir_add(root_dir, ".", ROOT_DIR_SECTOR);
    dir_add(root_dir, "..", ROOT_DIR_SECTOR);
    dir_close(root_dir);

	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

// 바로가기 file 생성
int symlink (const char *target, const char *linkpath) {
    // SOFT LINK
    bool success = false;
    char* cp_link = (char *)malloc(strlen(linkpath) + 1);
    strlcpy(cp_link, linkpath, strlen(linkpath) + 1);

    // cp_name의경로분석
    char* file_link = (char *)malloc(strlen(cp_link) + 1);
    struct dir* dir = parse_path(cp_link, file_link);

    cluster_t inode_cluster = fat_create_chain(0);

    // link file 전용 inode 생성 및 directory에 추가
    success = (dir != NULL
               && link_inode_create(inode_cluster, target)
               && dir_add(dir, file_link, inode_cluster));

    if (!success && inode_cluster != 0) {
        fat_remove_chain(inode_cluster, 0);
	}
    
    dir_close(dir);
    free(cp_link);
    free(file_link);

    return success - 1;
}

// link file 만드는 함수
bool link_inode_create (disk_sector_t sector, char* path_name) {

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (strlen(path_name) >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		disk_inode->length = strlen(path_name) + 1;
		disk_inode->magic = INODE_MAGIC;

        // link file 여부 추가
        disk_inode->is_dir = 0;
        disk_inode->is_link = 1;

        strlcpy(disk_inode->link_name, path_name, strlen(path_name) + 1);

        cluster_t cluster = fat_create_chain(0);
        if(cluster)
        {
            disk_inode->start = cluster;
            disk_write (filesys_disk, cluster_to_sector(sector), disk_inode);
            success = true;
        }

		free (disk_inode);
	}
	return success;
}

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t unused[125];               /* Not used. */

	uint32_t is_dir;					// 디렉토리 구분
    uint32_t is_link;                   // symlink 구분

    // 멤버 추가시마다 512바이트 맞추기
	char link_name[492];
};
