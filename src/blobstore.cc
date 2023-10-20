#include "witness/include/blobstore.h"
#include "witness/src/main.rs.h"
#include <stdio.h>
#include <string>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint8_t u8;

void Semaphore_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        std::string componentName, uint componentFather);

void Semaphore_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        std::string componentName, uint componentFather) {
  ctx->componentMemory[coffset].templateId = 0;
  ctx->componentMemory[coffset].templateName = "Semaphore";
  ctx->componentMemory[coffset].signalStart = soffset;
  ctx->componentMemory[coffset].inputCounter = 1;
  ctx->componentMemory[coffset].componentName = componentName;
  ctx->componentMemory[coffset].idFather = componentFather;
  ctx->componentMemory[coffset].subcomponents = rust::Vec<uint32_t>{};
}

void Semaphore_0_run(uint ctx_index, Circom_CalcWit *ctx) {
  rust::Vec<FrElement> &signalValues = ctx->signalValues;
  u64 mySignalStart = ctx->componentMemory[ctx_index].signalStart;
  rust::string myTemplateName = ctx->componentMemory[ctx_index].templateName;
  rust::string myComponentName = ctx->componentMemory[ctx_index].componentName;
  u64 myFather = ctx->componentMemory[ctx_index].idFather;
  u64 myId = ctx_index;
  rust::Vec<u32> mySubcomponents =
      ctx->componentMemory[ctx_index].subcomponents;
  rust::Vec<FrElement> &circuitConstants = ctx->circuitConstants;
  // std::string *listOfTemplateMessages = ctx->listOfTemplateMessages;

  rust::Vec<FrElement> expaux = create_vec(6);

  // std::unique_ptr<FrElement[]> lvar(new FrElement[0]);

  uint sub_component_aux;
  {
    FrElement *aux_dest = &signalValues[mySignalStart + 0];
    Fr_add(expaux[3], signalValues[mySignalStart + 1],
           circuitConstants[1]); // line circom 7

    // Fr_mul(expaux[1], circuitConstants[0], expaux[3]); // line circom 7
    // Fr_add(expaux[0], expaux[1], circuitConstants[2]); // line circom 7
    Fr_copy(aux_dest, &expaux[3]);
    // Fr_copyn(aux_dest, &expaux[0], 4);
  }
}

void run(Circom_CalcWit *ctx) {
  // Fr_mul(ctx->signalValues[0], ctx->signalValues[1], ctx->signalValues[2]);
  Semaphore_0_create(1, 0, ctx, "main", 0);
  Semaphore_0_run(0, ctx);
}
