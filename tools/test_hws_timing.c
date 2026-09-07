
static void receiver(const struct hws_dv_mode *m)
{
    memset(regs,0,sizeof(regs)); fault_offset=UINT32_MAX;fault_nth=fault_reads=0;fault_xor=16;
    set_reg(HWS_REG_ACTIVE_STATUS,1);
    set_reg(HWS_REG_IN_RES(0),(m->timings.bt.height<<16)|m->timings.bt.width);
    set_reg(HWS_REG_FRAME_RATE(0),m->refresh_hz);
}
static u64 gcd_test(u64 a,u64 b) {return b ? gcd_test(b,a%b) : a;}
int main(void)
{
    struct hws_pcie_dev h={.bar0_base=regs,.max_channels=4};
    struct hws_video *v=&h.video[0];v->parent=&h;v->state_lock=1;
    struct file file={.video=v};
    struct v4l2_streamparm p={.type=V4L2_BUF_TYPE_VIDEO_CAPTURE};
    struct v4l2_dv_timings t;
    struct v4l2_fract f;
    for(unsigned i=0;i<ARRAY_SIZE(hws_dv_modes);i++) {
        const struct hws_dv_mode *m=&hws_dv_modes[i];
        receiver(m); assert(!hws_vidioc_g_parm(&file,NULL,&p));
        assert(!hws_detect_dv_timings(v,&t,NULL));
        const struct v4l2_bt_timings *b=&t.bt;
        u64 pixels=((u64)b->width+b->hfrontporch+b->hsync+b->hbackporch)*
            ((u64)b->height+b->vfrontporch+b->vsync+b->vbackporch);
        f=p.parm.capture.timeperframe;
        assert((u64)f.numerator*b->pixelclock==(u64)f.denominator*pixels);
        assert(gcd_test(f.numerator,f.denominator)==1);
        assert(!hws_vidioc_s_dv_timings(&file,NULL,&t));
        assert(!hws_vidioc_g_dv_timings(&file,NULL,&t));
        assert(!memcmp(&t,&m->timings,sizeof(t)));
        assert(v->pix.sizeimage==b->width*b->height*2 &&
            v->pix.half_size==hws_video_native_split(v->pix.sizeimage));
        v->buffer_queue.busy=true;
        assert(!hws_vidioc_s_dv_timings(&file,NULL,&t));
        t=hws_dv_modes[(i+1)%ARRAY_SIZE(hws_dv_modes)].timings;
        assert(hws_vidioc_s_dv_timings(&file,NULL,&t)==-EBUSY);
        assert(!memcmp(&v->cur_dv_timings,&m->timings,sizeof(t)));
        v->buffer_queue.busy=false;
    }
    receiver(&hws_dv_modes[0]);
    /* A detected source change does not alter configured timing or layout. */
    struct v4l2_dv_timings configured=v->cur_dv_timings;
    struct hws_pix_state pix=v->pix;
    assert(!hws_vidioc_g_parm(&file,NULL,&p));
    assert(!memcmp(&configured,&v->cur_dv_timings,sizeof(configured)));
    assert(!memcmp(&pix,&v->pix,sizeof(pix)));
    resolution_error=-EIO;t=hws_dv_modes[0].timings;
    assert(hws_vidioc_s_dv_timings(&file,NULL,&t)==-EIO);
    assert(!memcmp(&pix,&v->pix,sizeof(pix)));resolution_error=0;
    set_reg(HWS_REG_ACTIVE_STATUS,0);
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-ENOLINK);
    assert(!p.parm.capture.timeperframe.numerator && !p.parm.capture.timeperframe.denominator);
    receiver(&hws_dv_modes[0]);set_reg(HWS_REG_FRAME_RATE(0),61);
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-ERANGE);
    for(unsigned field=0;field<3;field++) {
        receiver(&hws_dv_modes[0]);fault_kind=2;fault_nth=2;
        fault_offset=field==0 ? HWS_REG_FRAME_RATE(0) :
            field==1 ? HWS_REG_IN_RES(0) : HWS_REG_ACTIVE_STATUS;
        if(field<2) assert(hws_vidioc_g_parm(&file,NULL,&p)==-ENOLCK);
        else { /* another channel's active bit is irrelevant */
            assert(!hws_vidioc_g_parm(&file,NULL,&p));
        }
    }
    receiver(&hws_dv_modes[0]);fault_offset=HWS_REG_FRAME_RATE(0);fault_kind=3;fault_nth=2;
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-ENODEV && h.pci_lost);
    receiver(&hws_dv_modes[0]);h.pci_lost=h.dma_failed=false;h.suspended=true;
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-EBUSY);h.suspended=false;
    receiver(&hws_dv_modes[0]);fault_offset=HWS_REG_ACTIVE_STATUS;fault_kind=2;fault_nth=2;fault_xor=BIT(8);
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-ENOLCK);
    receiver(&hws_dv_modes[0]);fault_offset=HWS_REG_ACTIVE_STATUS;fault_kind=2;fault_nth=2;fault_xor=1;
    assert(hws_vidioc_g_parm(&file,NULL,&p)==-ENOLINK);
    t=hws_dv_modes[0].timings;t.bt.pixelclock=148351648;
    assert(!hws_dv_frame_period(&t,&f)); /* fractional clock, no nominal rounding */
    assert((u64)f.numerator*t.bt.pixelclock==(u64)f.denominator*2200*1125);
    assert(hws_vidioc_s_dv_timings(&file,NULL,&t)==-EINVAL); /* not advertised */
    t.bt.pixelclock=0;assert(hws_dv_frame_period(&t,&f)==-EINVAL);
    t=hws_dv_modes[0].timings;t.type=U32_MAX;assert(hws_dv_frame_period(&t,&f)==-EINVAL);
    t=hws_dv_modes[0].timings;t.bt.interlaced=1;assert(hws_dv_frame_period(&t,&f)==-EINVAL);
    t=hws_dv_modes[0].timings;t.bt.hfrontporch=U32_MAX;assert(hws_dv_frame_period(&t,&f)==-ERANGE);
    t=hws_dv_modes[0].timings;t.bt.pixelclock=U64_MAX;assert(hws_dv_frame_period(&t,&f)==-ERANGE);
    puts("Production timing contract PASS: 14 modes, exact reduced fractions, configured/detected separation, paired FPS/geometry, source errors, busy queue and invalid/overflow cases.");
    return 0;
}
