// Simple V4L2 capture demo supporting zero-copy and classic mmap paths.
// Build with `make` in this directory. Run with optional arguments to select
// device, frame count, and buffer memory type.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

#define DEFAULT_DEVICE   "/dev/video0"
#define DEFAULT_WIDTH    1280
#define DEFAULT_HEIGHT   720
#define DEFAULT_FRAMES   100
#define DEFAULT_BUFS     4

enum buffer_mode {
	MODE_MMAP,
	MODE_DMABUF,
};

struct buffer {
	void   *addr;
	size_t  length;
	int     dmabuf_fd;
};

static int xioctl(int fd, unsigned long req, void *arg)
{
	int r;
	do {
		r = ioctl(fd, req, arg);
	} while (r == -1 && errno == EINTR);
	return r;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-d device] [-n frames] [-m mmap|dmabuf]\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *devnode = DEFAULT_DEVICE;
	unsigned int frame_goal = DEFAULT_FRAMES;
	enum buffer_mode mode = MODE_MMAP;
	int opt;

	while ((opt = getopt(argc, argv, "d:n:m:h")) != -1) {
		switch (opt) {
		case 'd':
			devnode = optarg;
			break;
		case 'n':
			frame_goal = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 'm':
			if (!strcmp(optarg, "mmap"))
				mode = MODE_MMAP;
			else if (!strcmp(optarg, "dmabuf"))
				mode = MODE_DMABUF;
			else {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	int fd = open(devnode, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	struct v4l2_format fmt = {0};
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width = DEFAULT_WIDTH;
	fmt.fmt.pix.height = DEFAULT_HEIGHT;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
	fmt.fmt.pix.field = V4L2_FIELD_NONE;
	if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
		perror("VIDIOC_S_FMT");
		close(fd);
		return EXIT_FAILURE;
	}

	struct v4l2_requestbuffers req = {0};
	req.count = DEFAULT_BUFS;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = (mode == MODE_DMABUF) ? V4L2_MEMORY_DMABUF : V4L2_MEMORY_MMAP;
	if (xioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
		perror("VIDIOC_REQBUFS");
		close(fd);
		return EXIT_FAILURE;
	}

	if (req.count < DEFAULT_BUFS)
		fprintf(stderr, "Warning: driver only provided %u buffers\n", req.count);

	struct buffer *buffers = calloc(req.count, sizeof(*buffers));
	if (!buffers) {
		perror("calloc");
		close(fd);
		return EXIT_FAILURE;
	}

	for (unsigned int i = 0; i < req.count; ++i) {
		struct v4l2_buffer buf = {0};
		buf.type = req.type;
		buf.memory = req.memory;
		buf.index = i;

		if (mode == MODE_MMAP) {
			if (xioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
				perror("VIDIOC_QUERYBUF");
				goto cleanup;
			}
			buffers[i].length = buf.length;
			buffers[i].addr = mmap(NULL, buf.length,
					      PROT_READ | PROT_WRITE,
					      MAP_SHARED, fd, buf.m.offset);
			if (buffers[i].addr == MAP_FAILED) {
				perror("mmap");
				goto cleanup;
			}
		} else {
			/* For DMABUF we still need to QUERYBUF to learn length. */
			if (xioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
				perror("VIDIOC_QUERYBUF");
				goto cleanup;
			}
			buffers[i].length = buf.length;
			/* Export plane 0 to share with consumers (optional). */
			struct v4l2_exportbuffer exp = {
				.type = req.type,
				.index = i,
				.plane = 0,
			};
			if (xioctl(fd, VIDIOC_EXPBUF, &exp) < 0) {
				perror("VIDIOC_EXPBUF");
				goto cleanup;
			}
			buffers[i].dmabuf_fd = exp.fd;
			/* Users can import exp.fd into EGL/GL, GBM, etc. */
			close(exp.fd); /* demo doesn’t consume the fd itself */
		}

		if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
			perror("VIDIOC_QBUF");
			goto cleanup;
		}
	}

	enum v4l2_buf_type type = req.type;
	if (xioctl(fd, VIDIOC_STREAMON, &type) < 0) {
		perror("VIDIOC_STREAMON");
		goto cleanup;
	}

	for (unsigned int frame = 0; frame < frame_goal; ++frame) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		if (select(fd + 1, &fds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			perror("select");
			break;
		}

		struct v4l2_buffer buf = {0};
		buf.type = req.type;
		buf.memory = req.memory;
		if (xioctl(fd, VIDIOC_DQBUF, &buf) < 0) {
			if (errno == EAGAIN)
				continue;
			perror("VIDIOC_DQBUF");
			break;
		}

		printf("frame %3u: index=%u bytes=%u timestamp=%lld\n",
		       frame, buf.index, buf.bytesused,
		       (long long)buf.timestamp.tv_sec);

		/* process frame: buffers[buf.index].addr holds YUYV data in mmap mode.
		 * In DMABUF mode import the exported FD (see exp.fd comment above).
		 */

		if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
			perror("VIDIOC_QBUF");
			break;
		}
	}

	xioctl(fd, VIDIOC_STREAMOFF, &type);

cleanup:
	for (unsigned int i = 0; i < req.count; ++i) {
		if (mode == MODE_MMAP && buffers[i].addr && buffers[i].addr != MAP_FAILED)
			munmap(buffers[i].addr, buffers[i].length);
	}
	free(buffers);
	close(fd);
	return 0;
}
