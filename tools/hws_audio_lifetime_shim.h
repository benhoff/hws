/* Userspace test environment, never included in a module build. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#ifdef NDEBUG
#error Assertions are required
#endif
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned long snd_pcm_uframes_t;
typedef pthread_mutex_t spinlock_t;
struct mutex { pthread_mutex_t lock; };
struct work_struct { bool running; };
struct workqueue_struct { int unused; };
struct snd_pcm_runtime { char *dma_area; unsigned format, channels, buffer_size, period_size; };
struct snd_pcm_substream { struct snd_pcm_runtime *runtime; void *private_data; };
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define WRITE_ONCE(x,y) __atomic_store_n(&(x),(y),__ATOMIC_RELAXED)
#define spin_lock(l) assert(!pthread_mutex_lock(l))
#define spin_unlock(l) assert(!pthread_mutex_unlock(l))
#define spin_lock_irqsave(l,f) do { (f)=0; spin_lock(l); } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); spin_unlock(l); } while(0)
#define mutex_lock(l) spin_lock(&(l)->lock)
#define mutex_unlock(l) spin_unlock(&(l)->lock)
#define smp_wmb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define MAX_DMA_AUDIO_PK_SIZE 16
#define min(x,y) ((x)<(y)?(x):(y))
#define snd_pcm_substream_chip(ss) ((struct hws_audio *)(ss)->private_data)
static _Thread_local bool atomic_context;
#define might_sleep() assert(!atomic_context)
#define dev_dbg(...) ((void)0)
#define SNDRV_PCM_TRIGGER_START 0
#define SNDRV_PCM_TRIGGER_STOP 1
#define SNDRV_PCM_TRIGGER_RESUME 2
#define SNDRV_PCM_TRIGGER_SUSPEND 3
static void pause_worker(int point);
