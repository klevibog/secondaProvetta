
#define _GNU_SOURCE
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/inotify.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <dirent.h>
#include <openssl/evp.h>

#define DEBUG_MSG
#define FILE_SIZE 1024*1024*16
char * file_name;
/* 1* control errors , a:param di ritorno di fn/sys che vogliamo validare  */
#define CHECK_ERR(a,msg) {if ((a) == -1) { perror((msg)); exit(EXIT_FAILURE); } }
/* 1** control errors ,a:param di ritorno di fn/sys che vogliamo validare */
#define CHECK_ERR2_pthread(a,msg) {if ((a) != 0) { perror((msg)); exit(EXIT_FAILURE); } }

/* 2 control mmap errors */
#define CHECK_ERR_MMAP(a,msg) {if ((a) == MAP_FAILED) { perror((msg)); exit(EXIT_FAILURE); } }
//3
void parent_process_signal_handler(int signum);//signal handler fun
//4
void parent_process();//create randomize parent
//5
void child_process(int i);//create randomize child
//6
__off_t get_file_size(char * file_name) ;//get file size da nome file
//7
__off_t get_fd_size(char * file_name);//get file size da fd
//8
int create_file_set_size(char * file_name, unsigned int file_size);//create file
//8*
off_t show_current_file_offset(int fd);//uso lseek: in qesto caso SEEK_CUR
//9
char * find_largest_file_fd(int dir_fd, int explore_subdirectories_recursively,
		int * largest_file_size);//
//10
char * find_largest_file(char * directory_name, int explore_subdirectories_recursively,
		int * largest_file_size);//
//11
int is_file_a_directory(char * file_name);// controllare se nome file is a dir
//12
int is_fd_a_directory(int fd);//controllare se fd is a dir
//13
char * common_prepare_memory_map(char * fname, __off_t * file_size); //mmap function con file assoc
//13*
void * create_anon_mmap(size_t size);//mmap anonimous
//14
char* itoa_printf(int number); //integer to string convertion
//15
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;//static initializer di mutex
void * thread_function_MUTEX(void * arg);//thread sincro with mutex
//16
#define N 10
int count;
int number_of_threads = N;
sem_t mtx;
sem_t barrier;
void * thread_function_SEM_noNAME_BARRIER(void * arg);//sincro di thread/process with sem+barrier solution
//17
sem_t * a_arrived;//da inizializzare su main-> da distrugere poi su main
sem_t * b_arrived;//da inizializzare su main-> da distrugere poi
void* rendezvous_function(void* arg);//Rendezvous solution
//18
void swap(char *x, char *y);
//19
int * prepare_return_value(int value);//int to int* -> lo usi qunando thread_fn non ritorna void
//20
void freq_di_caratt();//calcolare la freq di ogni caratt di un array
//21
char * reverse(char * array, unsigned int i, unsigned int j);//reverse char array
//22
char * complete_reverse(char * array, unsigned int array_len);// reverse char array
//23
char * concat_arrays(char * array1, int array1_dimension, char * array2, int array2_dimension); //concatenare 2 char array
//24
void bubble_sort(int * array, int array_dimension);//sort of char array


//MAIN
int main(int argc, char * argv[]) {
	//freq_di_caratt();
	// create file
	unsigned int file_size = FILE_SIZE;
	char * char_vuoto[] = { NULL };// charr array 2D vuoto
	int* int_vuoto[]={0};// int array vuoto
		int res;
		int fd;
		char* text_to_write = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At ultrices mi tempus imperdiet nulla malesuada pellentesque elit. Non enim praesent elementum facilisis leo vel fringilla est ullamcorper. Non quam lacus suspendisse faucibus interdum. Metus vulputate eu scelerisque felis imperdiet. At ultrices mi tempus imperdiet nulla malesuada pellentesque. At tempor commodo ullamcorper a lacus vestibulum. Consequat semper viverra nam libero justo laoreet sit amet. Facilisis magna etiam tempor orci eu. Convallis tellus id interdum velit laoreet id donec ultrices. Interdum velit euismod in pellentesque massa placerat duis ultricies. Senectus et netus et malesuada fames. Pharetra vel turpis nunc eget lorem dolor. Nisi porta lorem mollis aliquam ut porttitor leo a. Euismod elementum nisi quis eleifend quam adipiscing vitae proin.";
		int text_to_write_len = strlen(text_to_write);
		char* addr;


//create (Open) file
		if (argc > 1) {
			file_name = argv[1];

			if (argc > 2) {
				unsigned int temp;
				res = sscanf(argv[2], "%u", &temp);
				if (res == 1)
					file_size = temp;
			}
		}

		fd = create_file_set_size(file_name, file_size);
		if (fd == -1) {
			exit(EXIT_FAILURE);
		}

//read file
		int bytes_read=0;
		int total_bytes_read=0;
		char* buffer;
		while ((bytes_read = read(fd, buffer, FILE_SIZE)) > 0) {
				printf("read() ha restituito %d bytes\n", bytes_read);

// facciamo qualcosa con i dati letti...
				total_bytes_read += bytes_read;
			}

			if (bytes_read == -1) {
				perror("read()");
			} else if (bytes_read == 0) {
				printf("OK, usciti da while per EOF (End Of File)\n");
			}
			printf("total_bytes_read = %u\n", total_bytes_read);
//write file
			int res = write(fd, text_to_write, text_to_write_len+1);
				if (res == -1) {
					perror("write()");
					exit(EXIT_FAILURE);
				}

//dup2
				  if (dup2(fd, STDIN_FILENO) == -1) {
				    	perror("problema con dup2");

				    	exit(EXIT_FAILURE);
				    }
				 //  fd=3;// non mi serve più
				      // attenzione che il file output.txt rimane aperto
				      close(fd);
//freee file, char*
			if (free(buffer) == -1) {
					perror("free");
					exit(EXIT_FAILURE);
				}
			if (close(fd) == -1) {
					perror("close");
					exit(EXIT_FAILURE);
				}
//-----------------------------------------------

//creating proccesses
			  for (int i = 0; i < N; i++) {
			    switch (fork()) {
			      case 0: // child process
			        child_process(i);
				exit(EXIT_SUCCESS);
			case -1:
				perror("fork()");
				exit(EXIT_FAILURE);
			default:

				parent_process();
				while (wait(NULL) != -1) ; // aspettiamo la terminazione di tutt i processi figli

				exit(EXIT_SUCCESS);
			}

	 }


//-------------------------------------------------------

// create pthread sincronized with thread_function_MUTEX

			pthread_t t1;
			pthread_t t2;
			void * result;

			int s;

			s = pthread_create(&t1, NULL, thread_function_MUTEX, NULL);

			if (s != 0) {
				perror("pthread_create");
				exit(EXIT_FAILURE);
			}

			s = pthread_create(&t2, NULL, thread_function_MUTEX, NULL);

			if (s != 0) {
				perror("pthread_create");
				exit(EXIT_FAILURE);
			}


			s = pthread_join(t1, &result);

			if (s != 0) {
				perror("pthread_join");
				exit(EXIT_FAILURE);
			}

			s = pthread_join(t2, &result);

			if (s != 0) {
				perror("pthread_join");
				exit(EXIT_FAILURE);
			}
//-------------------------------------------------------

//init sem di Barrier + destroy -> la stessa cosa deve essere fatto per ogni tipo di sem
		//	mtx=malloc(sizeof(sem_t));
		//	if(mtx == NULL){
		//			perror("malloc()\n");
		//			exit(1);
		//	barrier=malloc(sizeof(sem_t));
		//	if(barrier == NULL){
		//			perror("malloc()\n");
		//			exit(1);
			s = sem_init(&mtx,
							0, // 1 => il semaforo è condiviso tra processi,
							   // 0 => il semaforo è condiviso tra threads del processo
							1 // valore iniziale del semaforo
						  );

			CHECK_ERR(s,"sem_init")

			s = sem_init(&barrier,
								0, // 1 => il semaforo è condiviso tra processi,
								   // 0 => il semaforo è condiviso tra threads del processo
								0 // valore iniziale del semaforo
							  );
			/* codice*..*/
			s = sem_destroy(&mtx);
				CHECK_ERR(s,"sem_destroy")

				s = sem_destroy(&barrier);
				CHECK_ERR(s,"sem_destroy")
//---------------------------------------------------------

	return 0;
}

//
void parent_process_signal_handler(int signum) {
	// riceviamo SIGCHLD: Child stopped or terminated

	pid_t child_pid;

	// NON è sicuro chiamare printf da un signal handler!
	// printf non è async-signal-safe (vedere Kerrisk sezione 21.1.2)
	// printf è usato qui solo a scopo diagnostico/didattico
	printf("[parent] parent_process_signal_handler\n");

	child_pid = wait(NULL);

	printf("[parent] signal handler: process %u has terminated, exiting\n", child_pid);

	exit(EXIT_SUCCESS);
}

//
void parent_process() {

	char * addr;
	__off_t file_size;
	__off_t pos;
	char * previous_addr;

	// il processo padre registra il gestore di segnale per SIGCHLD
	if (signal(SIGCHLD, parent_process_signal_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	addr = common_prepare_memory_map(file_name, &file_size);

	if (addr == NULL) {
		exit(EXIT_FAILURE);
	}

	previous_addr = malloc(file_size);
	if (previous_addr == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	memcpy(previous_addr, addr, file_size);

	// monitora continuamente la memory map per cambiamenti apportati dall'altro processo
	// n.b.: non è la soluzione migliore in termini di sincronizzazione tra processi
	while (1) {
		for (pos = 0; pos < file_size; pos++) {
			if (addr[pos] != previous_addr[pos]) {
				printf("[parent] addr[%ld] has changed, new value: '%c'\n", pos, addr[pos]);
				break;
			}
		}

		memcpy(previous_addr, addr, file_size);
	}


}

//
void child_process(int i) {

	char * addr;
	__off_t file_size;
	char val = 'a';
	int counter = 0;

	addr = common_prepare_memory_map(file_name, &file_size);

	if (addr == NULL) {
		exit(EXIT_FAILURE);
	}

	// in una shell dentro la cartella di progetto eseguire (quando il file output.txt esiste già) :
	// watch -n 1 cat output.txt

	while (counter++ < 10) {

		printf("[child] before fill memory map with '%c'\n", val);

		for (__off_t i = 0; i < file_size; i++)
			addr[i] = val;

		val++;

		if (val > 'z')
			val = 'a';

		sleep(1); // il processo dorme un secondo
	}

	// non servirebbe perchè il processo non fa altro
	// e quindi ci penserà il kernel a liberare tutte le risorse usate dal processo
	if (munmap(addr, file_size) == -1) {
		perror("munmap");
	}

	printf("[child] terminating\n");

}

//
__off_t get_file_size(char * file_name) {

	struct stat sb;
	int res;

	res = stat(file_name, &sb);

	if (res == -1) {
		perror("stat()");
		return -1;
	}

	return sb.st_size;
}

//
__off_t get_fd_size(int fd) {

	struct stat sb;
	int res;

	res = fstat(fd, &sb);

	if (res == -1) {
		perror("fstat()");
		return -1;
	}

    // printf("File size: %lld bytes\n", (long long) sb.st_size);

	printf("sizeof(__off_t) = %lu\n", sizeof(__off_t));

    return sb.st_size;
}

//
int create_file_set_size(char * file_name, unsigned int file_size) {

	// apriamo il file in scrittura, se non esiste verrà creato,
	// se esiste già la sua dimensione viene troncata a 0

	// tratto da man 2 open
	// O_CREAT  If pathname does not exist, create it as a regular file.
	// O_TRUNC  If the file already exists and is a regular file and the access mode allows writing ... it will be truncated to length 0.
	// O_RDONLY, O_WRONLY, or O_RDWR  These request opening the file read-only, write-only, or read/write, respectively.
	off_t file_offset;
	int fd = open(file_name,
				  O_CREAT | O_RDWR,
				  S_IRUSR | S_IWUSR // l'utente proprietario del file avrà i permessi di lettura e scrittura sul nuovo file
				 );

	if (fd == -1) { // errore!
			perror("open()");
			return -1;
		}

	int res = ftruncate(fd, file_size);

	if (res == -1) {
		perror("ftruncate()");
		return -1;
	}

	return fd;
}

//
off_t show_current_file_offset(int fd) {

	off_t file_offset;

	file_offset = lseek(fd, 0, SEEK_CUR); // SEEK_CUR: posizione relativa rispetto alla posizione corrente

	if (file_offset == -1) {
		perror("lseek()");
		exit(EXIT_FAILURE);
	}

	printf("current file offset: %ld\n", file_offset);

	return file_offset;

}

//
char * find_largest_file_fd(int dir_fd, int explore_subdirectories_recursively,
		int * largest_file_size) {

	DIR * dir_stream_ptr;
	struct dirent *ep;

	dir_stream_ptr = fdopendir(dir_fd);

	if (dir_stream_ptr == NULL) {
		//printf("cannot open directory %s! bye", directory_name);
		*largest_file_size = -1;
		return NULL;
	}

	char * largest_file_name = malloc(256);
	int largest_file_len = -1;

	while ((ep = readdir(dir_stream_ptr)) != NULL) {

#ifdef DEBUG_MSG
		printf("%-10s ", (ep->d_type == DT_REG) ?  "regular" :
		                                    (ep->d_type == DT_DIR) ?  "directory" :
		                                    (ep->d_type == DT_FIFO) ? "FIFO" :
		                                    (ep->d_type == DT_SOCK) ? "socket" :
		                                    (ep->d_type == DT_LNK) ?  "symlink" :
		                                    (ep->d_type == DT_BLK) ?  "block dev" :
		                                    (ep->d_type == DT_CHR) ?  "char dev" : "???");

		printf("%s \n", ep->d_name);
#endif

		if (!strcmp(".", ep->d_name) || !strcmp("..", ep->d_name)) {
			continue;
		}

		// come trovo il file size? posso usare stat (man 2 stat)

		if (explore_subdirectories_recursively && ep->d_type == DT_DIR) { // directory

			int subdir_fd;
			char * sub_largest_file_name;
			int sub_largest_file_len;

			subdir_fd = openat(dir_fd, ep->d_name, O_RDONLY); // file descriptor della sub-directory

			if (subdir_fd == -1) {
				perror("openat");
				continue;
			}

			sub_largest_file_name = find_largest_file_fd(subdir_fd, explore_subdirectories_recursively, &sub_largest_file_len);

			if (sub_largest_file_name != NULL && sub_largest_file_len > largest_file_len) {
				strcpy(largest_file_name, sub_largest_file_name);
				largest_file_len = sub_largest_file_len;
			}

			free(sub_largest_file_name);

		} else if (ep->d_type == DT_REG) { // file regolare

			int file_fd;
			__off_t file_size;

			file_fd = openat(dir_fd, ep->d_name, O_PATH); // O_PATH è ok con fstat()

			file_size = get_fd_size(file_fd);

#ifdef DEBUG_MSG
			printf("%s size: %ld\n", ep->d_name, file_size);
#endif

			if (file_size > largest_file_len) {
				strcpy(largest_file_name, ep->d_name);
				largest_file_len = file_size;
			}

			close(file_fd);

		}
	}

	if (errno) {
		perror("readdir() error");
	}

	closedir(dir_stream_ptr);

	if (largest_file_len == -1) {
		*largest_file_size = -1;
		free(largest_file_name);
		return NULL;
	} else {

		*largest_file_size = largest_file_len;
		return largest_file_name;
	}
}

//
char * find_largest_file(char * directory_name, int explore_subdirectories_recursively,
		int * largest_file_size) {

	int dir_fd;

	dir_fd = open(directory_name, O_RDONLY);
	if (dir_fd == -1) {
		perror("open");
		printf("cannot open directory: %s\n", directory_name);
		exit(EXIT_FAILURE);
	}

	return find_largest_file_fd(dir_fd, explore_subdirectories_recursively, largest_file_size);
}

//
int is_file_a_directory(char * file_name) {

	struct stat sb;
	int res;

	res = stat(file_name, &sb);

	if (res == -1) {
		perror("stat()");
		return -1;
	}

	return (sb.st_mode & S_IFMT) == S_IFDIR;
}

//
int is_fd_a_directory(int fd) {

	struct stat sb;
	int res;

	res = fstat(fd, &sb);

	if (res == -1) {
		perror("fstat()");
		return -1;
	}

	return (sb.st_mode & S_IFMT) == S_IFDIR;
}

//
char * common_prepare_memory_map(char * fname, __off_t * file_size) {

	char * addr;

	// ipotesi: il file esiste già
	int fd = open(fname, O_RDWR); // apriamo il file in modalità read-write

	if (fd == -1) { // errore!
		perror("open()");
		return NULL;
	}

	*file_size = get_fd_size(fd);

	// mmap restituisce l'indirizzo della zona di memoria dove
	// è mappato tutto il file (o una sua parte)
	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			*file_size, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED, // memory map condivisibile con altri processi
			fd,
			0); // offset nel file

	close(fd);

	if (addr == MAP_FAILED) {
		perror("mmap()");
		return NULL;
	}

	return addr;
}

//
void * create_anon_mmap(size_t size) {

	// MAP_SHARED: condivisibile tra processi
	// PROT_READ | PROT_WRITE: posso leggere e scrivere nello spazio di memoria
	void * memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (memory == MAP_FAILED) {
		perror("mmap");

		return NULL;
	}

	return memory;

}

//
char* itoa_printf(int number) {
	char *result;

	// include '\0'
	//printf("minimum string len: %d\n",min_string_len(number));

	result = calloc(12, sizeof(char));

	snprintf(result, // zona di memoria in cui snprintf scriverà la stringa di caratteri
			12, // dimensione della zona di memoria
			"%d", // stringa di formattazione
			number); // numero intero da convertire in stringa
	//printf(" lungzz di stringa da interger %d\n",strlen(result));
	return result;
}

//
void * thread_function_MUTEX(void * arg) {
	int s;

	int op1_counter = 0;
	int op2_counter = 0;

	while (1) {

		s = pthread_mutex_lock(&mutex);
		if (s != 0) {
			perror("pthread_mutex_lock");
			exit(EXIT_FAILURE);
		}
// CRITICAL SECTION : ELLAB DI VAR CONDIVISE (TIPO VAR GLOBALI ECT)

/*	    counter++;
	    op1_counter++;

	    if (counter > LIMIT) {
	        counter = counter - LIMIT;
	        reset++;
	        op2_counter++;
	    }
*/
		s = pthread_mutex_unlock(&mutex);
		if (s != 0) {
			perror("pthread_mutex_lock");
			exit(EXIT_FAILURE);
		}

	}
	return NULL;
}

//
void * thread_function_SEM_noNAME_BARRIER(void * arg) {

	printf("rendezvous\n");

	//	mutex.wait()
	//	   count = count + 1
	//	mutex.signal()
	if (sem_wait(&mtx) == -1) {
		perror("sem_wait");
		exit(EXIT_FAILURE);
	}

	count++;

	if (sem_post(&mtx) == -1) {
		perror("sem_post");
		exit(EXIT_FAILURE);
	}
	//

	//	if count == n :
	//	   barrier.signal()
	if (count == number_of_threads) {
		if (sem_post(&barrier) == -1) {
			perror("sem_post");
			exit(EXIT_FAILURE);
		}
	}

	// turnstile (tornello)
	//	barrier.wait()
	//	barrier.signal()
	if (sem_wait(&barrier) == -1) {
		perror("sem_wait");
		exit(EXIT_FAILURE);
	}
	if (sem_post(&barrier) == -1) {
		perror("sem_post");
		exit(EXIT_FAILURE);
	}
	return NULL;

}

//
void* rendezvous_function(void* arg){

	int res;

		printf("Rendezvous: a1 < b2 && b1 < a2\n");

		a_arrived = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
				sizeof(sem_t) * 2, // dimensione della memory map
				PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
				MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi e senza file di appoggio
				-1,
				0); // offset nel file

		CHECK_ERR_MMAP(a_arrived,"mmap")

		b_arrived = a_arrived + 1;

		res = sem_init(a_arrived,
						1, // 1 => il semaforo è condiviso tra processi, 0 => il semaforo è condiviso tra threads del processo
						0 // valore iniziale del semaforo
					  );

		CHECK_ERR(res,"sem_init")

		res = sem_init(b_arrived,
						1, // 1 => il semaforo è condiviso tra processi, 0 => il semaforo è condiviso tra threads del processo
						0 // valore iniziale del semaforo
					  );

	printf("[child] statement a1\n");

			printf("[child] before a_arrived.signal()\n");

			// 3.3.2 Rendezvous solution (libro pag. 15)
			if (sem_post(a_arrived) == -1) {
				perror("sem_post");
				exit(EXIT_FAILURE);
			}

			printf("[child] before b_arrived.wait()\n");

			if (sem_wait(b_arrived) == -1) {
				perror("sem_wait");
				exit(EXIT_FAILURE);
			}

			printf("[child] statement a2\n");

			printf("[child] terminating\n");
			return NULL;


}

// swap char value
void swap(char *x, char *y) {
	char t = *x;
	*x = *y;
	*y = t;
}

//int to int*
int * prepare_return_value(int value) {

	int * result_value_ptr;

	result_value_ptr = malloc(sizeof(int));

	if (result_value_ptr == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	*result_value_ptr = value;

	return result_value_ptr;
}

//calcolare la freq di caratt
void freq_di_caratt(){
	char * a ="abcdefghilmnopqrstuvz123!";
	int c[256]={0};
	for (int i = 0; a[i] != NULL; i++) {
			c[(int)a[i]]++;
	}
	for(int i=0; i<256; i++)
		printf("la frequenza di caratt '%c' nel testo:'abcdefghilmnopqrstuvz123' = %d\n",(char)i,c[i]);
}

// function to reverse array[i..j]
char * reverse(char * array, unsigned int i, unsigned int j)
{
//	while (i < j)
//		swap(&array[i++], &array[--j]);

	while (i < j) {
		j--;
		swap(&array[i], &array[j]);
		i++;
	}

	return array;
}

//
char * complete_reverse(char * array, unsigned int array_len) {
	return reverse(array, 0, array_len);
}

//
void bubble_sort(int * array, int array_dimension) {

	// ESERCIZIO: implementare bubble sort (pseudocodice riportato sotto)

	int n = array_dimension;
	int newn;
	do {
		newn = 0;
		for (int i = 1; i < n; i++) {
			if (array[i-1] > array[i]) {
				swap(&array[i-1], &array[i]);
				newn = i;
			}

		}

		n = newn;

	} while (n > 1);



}

//
char *concat_arrays(char *array1, int array1_dim, char *array2, int array2_dim) {

	char *new_array;

	int tot_len = array1_dim + array2_dim;

	new_array = malloc(sizeof(char)*tot_len);

	if (new_array == NULL) {
		perror("malloc ha restituito errore");
		return NULL;
	}

	for (int i=0; i<array1_dim; i++) {
		new_array[i] = array1[i];
	}

	for (int j=array1_dim; j<tot_len; j++) {
		new_array[j] = array2[j - array1_dim];
	}

	return new_array;
}
