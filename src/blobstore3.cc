#include "witness/include/blobstore.h"
#include "witness/src/main.rs.h"

/// We need this accessor since cxx doesn't support hashmaps yet
class IOSignalInfoAccessor {
private:
  Circom_CalcWit *calcWitContext;

public:
  explicit IOSignalInfoAccessor(Circom_CalcWit *calcWit)
      : calcWitContext(calcWit) {}
  auto operator[](size_t index) const -> decltype(auto) {
    return (calcWitContext
                ->templateInsId2IOSignalInfoList)[index % get_size_of_io_map()]
        .list;
  }
};

typedef void (*Circom_TemplateFunction)(uint __cIdx, Circom_CalcWit *__ctx);

//////////////////////////////////////////////////////////////////
/// Generated code from circom compiler below
//////////////////////////////////////////////////////////////////

void Semaphore_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        rust::string componentName, uint componentFather);
void Semaphore_0_run(uint ctx_index, Circom_CalcWit *ctx);
Circom_TemplateFunction _functionTable[1] = {Semaphore_0_run};
uint get_main_input_signal_start() { return 2; }

uint get_main_input_signal_no() { return 1; }

uint get_total_signal_no() { return 3; }

uint get_number_of_components() { return 1; }

uint get_size_of_input_hashmap() { return 256; }

uint get_size_of_witness() { return 2; }

uint get_size_of_constants() { return 3; }

uint get_size_of_io_map() { return 0; }

// function declarations
// template declarations
void Semaphore_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        rust::string componentName, uint componentFather) {
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
  rust::Vec<rust::string> &listOfTemplateMessages = ctx->listOfTemplateMessages;
  rust::Vec<FrElement> expaux = create_vec(6);
  rust::Vec<FrElement> lvar = create_vec(0);
  uint sub_component_aux;
  {
    FrElement *aux_dest = &signalValues[mySignalStart + 0];
    // load src
    Fr_sub(&expaux[3], &signalValues[mySignalStart + 1],
           &circuitConstants[1]);                         // line circom 7
    Fr_mul(&expaux[1], &circuitConstants[0], &expaux[3]); // line circom 7
    Fr_add(&expaux[0], &expaux[1], &circuitConstants[2]); // line circom 7
    // end load src
    Fr_copy(aux_dest, &expaux[0]);
  }
}

void run(Circom_CalcWit *ctx) {
  Semaphore_0_create(1, 0, ctx, "main", 0);
  Semaphore_0_run(0, ctx);
}
