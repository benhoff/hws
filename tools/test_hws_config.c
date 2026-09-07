
static void init(struct hws_pcie_dev *h)
{
    memset(h,0,sizeof(*h));memset(regs,0,sizeof(regs));
    h->bar0_base=regs;h->max_channels=h->cur_max_video_ch=h->cur_max_audio_ch=4;
    struct hws_video *v=&h->video[0];v->parent=h;v->irq_lock=1;
    v->pix=(struct hws_pix_state){.width=1920,.height=1080,.bytesperline=3840,
        .sizeimage=4147200,.half_size=hws_video_native_split(4147200),
        .fourcc=V4L2_PIX_FMT_YUYV,.field=V4L2_FIELD_NONE};
    fault_offset=UINT32_MAX;fault_kind=write_count=shared_writes=0;
    fault_reads=fault_nth=0;fault_xor=16;
}
int main(void)
{
    const unsigned offsets[]={PCI_ADDR_TABLE_BASE+HWS_VIDEO_REMAP_SLOT_OFF(0),
        PCI_ADDR_TABLE_BASE+HWS_VIDEO_REMAP_SLOT_OFF(0)+PCIE_BARADDROFSIZE,
        HWS_REG_VIDEO_DMA_ADDR(0),HWS_REG_VIDEO_HALF_SIZE(0)};
    struct hws_pcie_dev h;
    for(unsigned debug=0;debug<2;debug++) for(unsigned warm=0;warm<2;warm++)
    for(unsigned field=0;field<4;field++) for(unsigned fault=1;fault<=3;fault++) {
        init(&h);dma_window_verify=debug;struct hws_video *v=&h.video[0];
        if(warm) {
            assert(!hws_program_video_ring_locked(v));
            v->pix.width=1280;v->pix.height=720;
            v->pix.bytesperline=2560;v->pix.sizeimage=2560*720;
            v->pix.half_size=hws_video_native_split(v->pix.sizeimage);
        }
        /* A stale nonzero value makes every dropped-write case observable. */
        u32 old_hi=v->last_dma_hi,old_page=v->last_dma_page;
        u32 old_base=v->last_pci_addr,old_split=v->last_half16;
        set_reg(offsets[field],0xdeadbeef);fault_offset=offsets[field];fault_kind=fault;
        assert(hws_program_video_ring_locked(v)<0);
        assert(!v->window_valid && !v->cap_active);
        assert(v->last_dma_hi==old_hi && v->last_dma_page==old_page &&
            v->last_pci_addr==old_base && v->last_half16==old_split);
        unsigned writes=write_count;
        hws_enable_video_capture(&h,0,true);
        assert(!(get_reg(HWS_REG_VCAP_ENABLE)&1) && write_count==writes);
    }
    init(&h);assert(!hws_program_video_ring_locked(&h.video[0]));
    hws_enable_video_capture(&h,0,true);assert(h.video[0].cap_active);
    unsigned writes=write_count;
    assert(hws_program_video_ring_locked(&h.video[0])==-EBUSY && writes==write_count);
    init(&h);set_reg(HWS_REG_VCAP_ENABLE,1);
    assert(hws_program_video_ring_locked(&h.video[0])==-EBUSY && !write_count);
    assert(!h.video[0].window_valid);
    init(&h);h.video[0].dma_needs_idle=h.video[0].window_valid=true;
    assert(hws_program_video_ring_locked(&h.video[0])==-EBUSY && !write_count);
    assert(h.video[0].dma_needs_idle && !h.video[0].window_valid);
    init(&h);assert(!hws_program_video_ring_locked(&h.video[0]));
    set_reg(HWS_REG_ACAP_ENABLE,1);set_reg(HWS_REG_VCAP_ENABLE,BIT(1));
    set_reg(HWS_REG_AUD_DMA_ADDR(0),0xabcdef);shared_writes=0;
    assert(!hws_program_video_ring_locked(&h.video[0]) && !shared_writes);
    assert(get_reg(HWS_REG_ACAP_ENABLE)==1 && get_reg(HWS_REG_VCAP_ENABLE)==BIT(1));
    assert(get_reg(HWS_REG_AUD_DMA_ADDR(0))==0xabcdef);
    set_reg(offsets[0],0xbad);writes=write_count;
    assert(hws_program_video_ring_locked(&h.video[0])<0 && write_count==writes);
    assert(get_reg(HWS_REG_ACAP_ENABLE)==1 && !shared_writes);
    /* Converse direction: audio must not rewrite an active video's remap. */
    init(&h);assert(!hws_program_video_ring_locked(&h.video[0]));
    set_reg(HWS_REG_VCAP_ENABLE,1);shared_writes=0;
    assert(!hws_program_dma_window(&h,0,ring_dma+0x10000,0,true,true));
    assert(!shared_writes && get_reg(HWS_REG_VCAP_ENABLE)==1);
    writes=write_count;
    assert(hws_program_dma_window(&h,0,ring_dma+(1ULL<<32),0,true,true)<0);
    assert(write_count==writes && !shared_writes);
    /* Audio base exception is zero only at probe/resume, never stream start. */
    init(&h);fault_offset=HWS_REG_AUD_DMA_ADDR(0);fault_kind=1;
    assert(!hws_program_dma_window(&h,0,ring_dma,0,true,false));
    assert(hws_program_dma_window(&h,0,ring_dma,0,true,true)==-EIO);
    set_reg(fault_offset,0xbad);
    assert(hws_program_dma_window(&h,0,ring_dma,0,true,false)==-EIO);
    for(unsigned audio=0;audio<2;audio++) for(unsigned field=0;field<2;field++) {
        init(&h);fault_offset=field ? HWS_REG_ACAP_ENABLE : HWS_REG_VCAP_ENABLE;
        fault_kind=3;
        assert(hws_program_dma_window(&h,0,ring_dma,1,audio,true)==-ENODEV);
        assert(h.pci_lost && !write_count);
    }
    puts("Production DMA configuration PASS: 48 register faults; cache/arm gate; bidirectional active-peer preservation; capture-status loss and idle-audio exception.");
    return 0;
}
