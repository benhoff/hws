"""Hardware-free tests of extracted production configuration functions."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from test_audio_lifetime import function

ROOT = Path(__file__).resolve().parents[1]


def config_prefix():
    h = (ROOT/'src/hws.h').read_text()
    reg = (ROOT/'src/hws_reg.h').read_text()
    import re
    reg = re.sub(r'^#include[^\n]*$', '', reg, flags=re.M)
    shim = (ROOT/'tools/hws_config_test_shim.h').read_text()
    layout = h[h.index('struct hws_pix_state {'):h.index('#define\tUNSET')]
    return shim.split('/* DEVICE */')[0] + reg + layout + shim.split('/* DEVICE */')[1]


def dma_code():
    video = (ROOT/'src/hws_video.c').read_text()
    code = config_prefix() + (ROOT/'src/hws_dma_config.h').read_text()
    code += function(video, 'hws_program_video_ring_locked')
    code += '\n' + function(video, 'hws_enable_video_capture')
    return code + (ROOT/'tools/test_hws_config.c').read_text()


def timing_code():
    src = (ROOT/'src/hws_v4l2_ioctl.c').read_text()
    code = config_prefix()
    code += (ROOT/'src/hws_timing.h').read_text()
    code += r'''
struct file { struct hws_video *video; };
#define video_drvdata(f) ((f)->video)
static int resolution_error;
static int hws_video_set_output_resolution(struct hws_video *v,u32 w,u32 h)
{ (void)v;(void)w;(void)h;return resolution_error; }
static bool vb2_is_busy(struct vb2_queue *q) {return q->busy;}
static bool v4l2_match_dv_timings(const struct v4l2_dv_timings *a,
    const struct v4l2_dv_timings *b,unsigned delta,bool reduced)
{(void)delta;(void)reduced;return !memcmp(a,b,sizeof(*a));}
'''
    code += src[src.index('struct hws_dv_mode {'):src.index('static inline u32 hws_calc_half_size')]
    code += 'static u32 hws_calc_half_size(u32 s) {return hws_video_native_split(s);}\n'
    begin = src.index('static const struct hws_dv_mode *\nhws_match_supported_dv')
    code += src[begin:src.index('static u32 hws_input_status', begin)]
    for name in ('hws_vidioc_g_parm', 'hws_vidioc_g_dv_timings', 'hws_vidioc_s_dv_timings'):
        code += '\n' + function(src, name)
    return code + (ROOT/'tools/test_hws_timing.c').read_text()


class ConfigurationTests(unittest.TestCase):
    def test_dma_transaction(self):
        self.compile_run(dma_code())

    def test_timing_contract(self):
        self.compile_run(timing_code())

    def test_callers_and_snapshot_locking(self):
        video = (ROOT/'src/hws_video.c').read_text()
        audio = (ROOT/'src/hws_audio.c').read_text()
        for source, name in ((video, 'hws_program_video_ring_locked'),
                             (video, 'hws_seed_dma_windows'),
                             (audio, 'hws_audio_seed_capture_buffer_locked')):
            self.assertIn('hws_program_dma_window(', function(source, name))
        start = function(video, 'hws_start_streaming')
        self.assertIn('ret = hws_program_video_ring_locked(v);\n\tif (!ret)', start)
        snapshot = function((ROOT/'src/hws_debugfs.c').read_text(), 'hws_debugfs_config_show')
        self.assertLess(snapshot.index('mutex_lock(&v->state_lock)'), snapshot.index('hws_dv_frame_period('))
        self.assertGreater(snapshot.index('mutex_unlock(&v->state_lock)'), snapshot.index('frame_period_num='))

    def test_removed_checks_are_detected(self):
        cases = [
            ('DMA equality', dma_code(),
             'if (actual != expected && (exact || actual != 0))', 'if (false)'),
            ('shared peer guard', dma_code(), 'if (!peer_active) {', 'if (true) {'),
            ('rational period', timing_code(), 'param->parm.capture.timeperframe = period;',
             'param->parm.capture.timeperframe = (struct v4l2_fract){1,60};'),
            ('paired FPS', timing_code(), 'res0 != res1 || live_fps != fps1 ||', 'res0 != res1 ||'),
        ]
        for name, code, before, after in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='hws-config-mutation-') as tmp:
                self.assertEqual(code.count(before), 1)
                path=Path(tmp)
                (path/'test.c').write_text(code.replace(before, after))
                subprocess.run(['cc', '-std=gnu11', '-O1', str(path/'test.c'),
                                '-o', str(path/'test')], check=True)
                result = subprocess.run([str(path/'test')], capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Assertion', result.stderr)

    def compile_run(self, code):
        with tempfile.TemporaryDirectory(prefix='hws-config-') as tmp:
            path = Path(tmp)
            (path/'test.c').write_text(code)
            flags = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-function',
                     '-Wno-unused-variable', '-Wno-unused-parameter', '-Wno-sign-compare', '-Werror', '-O1', '-g']
            if os.environ.get('HWS_CONFIG_SANITIZE') == '1':
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(['cc', *flags, str(path/'test.c'), '-o', str(path/'test')], check=True)
            subprocess.run([str(path/'test')], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
