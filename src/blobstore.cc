#include "witness/include/blobstore.h"
#include "iostream"
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
                ->templateInsId2IOSignalInfoList)[index % get_size_of_io_map()];
  }
};

typedef void (*Circom_TemplateFunction)(uint __cIdx, Circom_CalcWit *__ctx);

//////////////////////////////////////////////////////////////////
/// Generated code from circom compiler below
//////////////////////////////////////////////////////////////////

void MiMC7_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                    rust::string componentName, uint componentFather);
void MiMC7_0_run(uint ctx_index, Circom_CalcWit *ctx);
void Semaphore_1_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        rust::string componentName, uint componentFather);
void Semaphore_1_run(uint ctx_index, Circom_CalcWit *ctx);
Circom_TemplateFunction _functionTable[2] = {MiMC7_0_run, Semaphore_1_run};
Circom_TemplateFunction _functionTableParallel[2] = {NULL, NULL};
uint get_main_input_signal_start() { return 2; }

uint get_main_input_signal_no() { return 1; }

uint get_total_signal_no() { return 45; }

uint get_number_of_components() { return 2; }

uint get_size_of_input_hashmap() { return 256; }

uint get_size_of_witness() { return 42; }

uint get_size_of_constants() { return 181; }

uint get_size_of_io_map() { return 0; }

void release_memory_component(Circom_CalcWit *ctx, uint pos) {
  {}
}

// function declarations
// template declarations
void MiMC7_0_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                    rust::string componentName, uint componentFather) {
  ctx->componentMemory[coffset].templateId = 0;
  ctx->componentMemory[coffset].templateName = "MiMC7";
  ctx->componentMemory[coffset].signalStart = soffset;
  ctx->componentMemory[coffset].inputCounter = 2;
  ctx->componentMemory[coffset].componentName = componentName;
  ctx->componentMemory[coffset].idFather = componentFather;
  ctx->componentMemory[coffset].subcomponents = rust::Vec<uint32_t>{};
}

void MiMC7_0_run(uint ctx_index, Circom_CalcWit *ctx) {
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
  rust::Vec<FrElement> lvar = create_vec(94);
  uint sub_component_aux;
  {
    FrElement *aux_dest = &lvar[0];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[0]);
  }
  {
    FrElement *aux_dest = &lvar[1];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[1]);
  }
  {
    FrElement *aux_dest = &lvar[2];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[3]);
  }
  {
    FrElement *aux_dest = &lvar[3];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[5]);
  }
  {
    FrElement *aux_dest = &lvar[4];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[7]);
  }
  {
    FrElement *aux_dest = &lvar[5];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[9]);
  }
  {
    FrElement *aux_dest = &lvar[6];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[11]);
  }
  {
    FrElement *aux_dest = &lvar[7];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[13]);
  }
  {
    FrElement *aux_dest = &lvar[8];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[15]);
  }
  {
    FrElement *aux_dest = &lvar[9];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[17]);
  }
  {
    FrElement *aux_dest = &lvar[10];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[19]);
  }
  {
    FrElement *aux_dest = &lvar[11];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[20]);
  }
  {
    FrElement *aux_dest = &lvar[12];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[22]);
  }
  {
    FrElement *aux_dest = &lvar[13];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[24]);
  }
  {
    FrElement *aux_dest = &lvar[14];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[26]);
  }
  {
    FrElement *aux_dest = &lvar[15];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[28]);
  }
  {
    FrElement *aux_dest = &lvar[16];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[30]);
  }
  {
    FrElement *aux_dest = &lvar[17];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[32]);
  }
  {
    FrElement *aux_dest = &lvar[18];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[34]);
  }
  {
    FrElement *aux_dest = &lvar[19];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[36]);
  }
  {
    FrElement *aux_dest = &lvar[20];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[38]);
  }
  {
    FrElement *aux_dest = &lvar[21];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[40]);
  }
  {
    FrElement *aux_dest = &lvar[22];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[42]);
  }
  {
    FrElement *aux_dest = &lvar[23];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[44]);
  }
  {
    FrElement *aux_dest = &lvar[24];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[46]);
  }
  {
    FrElement *aux_dest = &lvar[25];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[48]);
  }
  {
    FrElement *aux_dest = &lvar[26];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[50]);
  }
  {
    FrElement *aux_dest = &lvar[27];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[52]);
  }
  {
    FrElement *aux_dest = &lvar[28];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[54]);
  }
  {
    FrElement *aux_dest = &lvar[29];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[56]);
  }
  {
    FrElement *aux_dest = &lvar[30];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[58]);
  }
  {
    FrElement *aux_dest = &lvar[31];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[60]);
  }
  {
    FrElement *aux_dest = &lvar[32];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[62]);
  }
  {
    FrElement *aux_dest = &lvar[33];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[64]);
  }
  {
    FrElement *aux_dest = &lvar[34];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[66]);
  }
  {
    FrElement *aux_dest = &lvar[35];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[68]);
  }
  {
    FrElement *aux_dest = &lvar[36];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[70]);
  }
  {
    FrElement *aux_dest = &lvar[37];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[72]);
  }
  {
    FrElement *aux_dest = &lvar[38];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[74]);
  }
  {
    FrElement *aux_dest = &lvar[39];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[76]);
  }
  {
    FrElement *aux_dest = &lvar[40];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[78]);
  }
  {
    FrElement *aux_dest = &lvar[41];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[80]);
  }
  {
    FrElement *aux_dest = &lvar[42];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[82]);
  }
  {
    FrElement *aux_dest = &lvar[43];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[84]);
  }
  {
    FrElement *aux_dest = &lvar[44];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[86]);
  }
  {
    FrElement *aux_dest = &lvar[45];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[88]);
  }
  {
    FrElement *aux_dest = &lvar[46];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[90]);
  }
  {
    FrElement *aux_dest = &lvar[47];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[92]);
  }
  {
    FrElement *aux_dest = &lvar[48];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[94]);
  }
  {
    FrElement *aux_dest = &lvar[49];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[96]);
  }
  {
    FrElement *aux_dest = &lvar[50];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[98]);
  }
  {
    FrElement *aux_dest = &lvar[51];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[100]);
  }
  {
    FrElement *aux_dest = &lvar[52];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[102]);
  }
  {
    FrElement *aux_dest = &lvar[53];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[104]);
  }
  {
    FrElement *aux_dest = &lvar[54];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[106]);
  }
  {
    FrElement *aux_dest = &lvar[55];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[108]);
  }
  {
    FrElement *aux_dest = &lvar[56];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[110]);
  }
  {
    FrElement *aux_dest = &lvar[57];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[112]);
  }
  {
    FrElement *aux_dest = &lvar[58];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[114]);
  }
  {
    FrElement *aux_dest = &lvar[59];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[116]);
  }
  {
    FrElement *aux_dest = &lvar[60];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[118]);
  }
  {
    FrElement *aux_dest = &lvar[61];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[120]);
  }
  {
    FrElement *aux_dest = &lvar[62];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[122]);
  }
  {
    FrElement *aux_dest = &lvar[63];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[124]);
  }
  {
    FrElement *aux_dest = &lvar[64];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[126]);
  }
  {
    FrElement *aux_dest = &lvar[65];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[128]);
  }
  {
    FrElement *aux_dest = &lvar[66];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[130]);
  }
  {
    FrElement *aux_dest = &lvar[67];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[132]);
  }
  {
    FrElement *aux_dest = &lvar[68];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[134]);
  }
  {
    FrElement *aux_dest = &lvar[69];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[136]);
  }
  {
    FrElement *aux_dest = &lvar[70];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[138]);
  }
  {
    FrElement *aux_dest = &lvar[71];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[140]);
  }
  {
    FrElement *aux_dest = &lvar[72];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[142]);
  }
  {
    FrElement *aux_dest = &lvar[73];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[144]);
  }
  {
    FrElement *aux_dest = &lvar[74];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[146]);
  }
  {
    FrElement *aux_dest = &lvar[75];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[148]);
  }
  {
    FrElement *aux_dest = &lvar[76];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[150]);
  }
  {
    FrElement *aux_dest = &lvar[77];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[152]);
  }
  {
    FrElement *aux_dest = &lvar[78];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[154]);
  }
  {
    FrElement *aux_dest = &lvar[79];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[156]);
  }
  {
    FrElement *aux_dest = &lvar[80];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[158]);
  }
  {
    FrElement *aux_dest = &lvar[81];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[160]);
  }
  {
    FrElement *aux_dest = &lvar[82];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[162]);
  }
  {
    FrElement *aux_dest = &lvar[83];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[164]);
  }
  {
    FrElement *aux_dest = &lvar[84];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[166]);
  }
  {
    FrElement *aux_dest = &lvar[85];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[168]);
  }
  {
    FrElement *aux_dest = &lvar[86];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[170]);
  }
  {
    FrElement *aux_dest = &lvar[87];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[172]);
  }
  {
    FrElement *aux_dest = &lvar[88];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[174]);
  }
  {
    FrElement *aux_dest = &lvar[89];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[176]);
  }
  {
    FrElement *aux_dest = &lvar[90];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[178]);
  }
  {
    FrElement *aux_dest = &lvar[91];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[180]);
  }
  {
    FrElement *aux_dest = &lvar[92];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[1]);
  }
  {
    FrElement *aux_dest = &lvar[93];
    // load src
    // end load src
    Fr_copy(aux_dest, &circuitConstants[1]);
  }
  Fr_lt(&expaux[0], &lvar[93], &circuitConstants[0]); // line circom 108
  while (Fr_isTrue(&expaux[0])) {
    Fr_eq(&expaux[0], &lvar[93], &circuitConstants[1]); // line circom 109
    if (Fr_isTrue(&expaux[0])) {
      {
        FrElement *aux_dest = &lvar[92];
        // load src
        Fr_add(&expaux[0], &signalValues[mySignalStart + 2],
               &signalValues[mySignalStart + 1]); // line circom 109
        // end load src
        Fr_copy(aux_dest, &expaux[0]);
      }
    } else {
      {
        FrElement *aux_dest = &lvar[92];
        // load src
        Fr_sub(&expaux[3], &lvar[93], &circuitConstants[2]); // line circom 109
        Fr_add(&expaux[1], &signalValues[mySignalStart + 2],
               &signalValues[mySignalStart + ((1 * Fr_toInt(&expaux[3])) +
                                              33)]); // line circom 109
        Fr_add(&expaux[0], &expaux[1],
               &lvar[((1 * Fr_toInt(&lvar[93])) + 1)]); // line circom 109
        // end load src
        Fr_copy(aux_dest, &expaux[0]);
      }
    }
    {
      FrElement *aux_dest =
          &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 3)];
      // load src
      Fr_mul(&expaux[0], &lvar[92], &lvar[92]); // line circom 110
      // end load src
      Fr_copy(aux_dest, &expaux[0]);
    }
    {
      FrElement *aux_dest =
          &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 13)];
      // load src
      Fr_mul(&expaux[0],
             &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 3)],
             &signalValues[mySignalStart +
                           ((1 * Fr_toInt(&lvar[93])) + 3)]); // line circom 111
      // end load src
      Fr_copy(aux_dest, &expaux[0]);
    }
    {
      FrElement *aux_dest =
          &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 23)];
      // load src
      Fr_mul(&expaux[0],
             &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 13)],
             &signalValues[mySignalStart +
                           ((1 * Fr_toInt(&lvar[93])) + 3)]); // line circom 112
      // end load src
      Fr_copy(aux_dest, &expaux[0]);
    }
    Fr_lt(&expaux[0], &lvar[93], &circuitConstants[18]); // line circom 113
    if (Fr_isTrue(&expaux[0])) {
      {
        FrElement *aux_dest =
            &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 33)];
        // load src
        Fr_mul(&expaux[0],
               &signalValues[mySignalStart + ((1 * Fr_toInt(&lvar[93])) + 23)],
               &lvar[92]); // line circom 114
        // end load src
        Fr_copy(aux_dest, &expaux[0]);
      }
    } else {
      {
        FrElement *aux_dest = &signalValues[mySignalStart + 0];
        // load src
        Fr_mul(&expaux[1], &signalValues[mySignalStart + 32],
               &lvar[92]); // line circom 116
        Fr_add(&expaux[0], &expaux[1],
               &signalValues[mySignalStart + 2]); // line circom 116
        // end load src
        Fr_copy(aux_dest, &expaux[0]);
      }
    }
    {
      FrElement *aux_dest = &lvar[93];
      // load src
      Fr_add(&expaux[0], &lvar[93], &circuitConstants[2]); // line circom 108
      // end load src
      Fr_copy(aux_dest, &expaux[0]);
    }
    Fr_lt(&expaux[0], &lvar[93], &circuitConstants[0]); // line circom 108
  }
  for (uint i = 0; i < 0; i++) {
    uint index_subc = ctx->componentMemory[ctx_index].subcomponents[i];
    release_memory_component(ctx, index_subc);
  }
}

void Semaphore_1_create(uint soffset, uint coffset, Circom_CalcWit *ctx,
                        rust::string componentName, uint componentFather) {
  ctx->componentMemory[coffset].templateId = 1;
  ctx->componentMemory[coffset].templateName = "Semaphore";
  ctx->componentMemory[coffset].signalStart = soffset;
  ctx->componentMemory[coffset].inputCounter = 1;
  ctx->componentMemory[coffset].componentName = componentName;
  ctx->componentMemory[coffset].idFather = componentFather;
  ctx->componentMemory[coffset].subcomponents = rust::Vec<uint32_t>{0};
}

void Semaphore_1_run(uint ctx_index, Circom_CalcWit *ctx) {
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
  rust::Vec<FrElement> expaux = create_vec(2);
  rust::Vec<FrElement> lvar = create_vec(0);
  uint sub_component_aux;
  {
    uint aux_create = 0;
    int aux_cmp_num = 0 + ctx_index + 1;
    uint csoffset = mySignalStart + 2;
    for (uint i = 0; i < 1; i++) {
      rust::string new_cmp_name = "hash";
      MiMC7_0_create(csoffset, aux_cmp_num, ctx, new_cmp_name, myId);
      mySubcomponents[aux_create + i] = aux_cmp_num;
      csoffset += 42;
      aux_cmp_num += 1;
    }
  }
  {
    uint cmp_index_ref = 0;
    {
      FrElement *aux_dest =
          &ctx->signalValues
               [ctx->componentMemory[mySubcomponents[cmp_index_ref]]
                    .signalStart +
                1];
      // load src
      // end load src
      Fr_copy(aux_dest, &signalValues[mySignalStart + 1]);
    }
    // no need to run sub component
    assert(--ctx->componentMemory[mySubcomponents[cmp_index_ref]].inputCounter);
  }
  {
    uint cmp_index_ref = 0;
    {
      FrElement *aux_dest =
          &ctx->signalValues
               [ctx->componentMemory[mySubcomponents[cmp_index_ref]]
                    .signalStart +
                2];
      // load src
      // end load src
      Fr_copy(aux_dest, &circuitConstants[0]);
    }
    // need to run sub component
    assert(
        !(--ctx->componentMemory[mySubcomponents[cmp_index_ref]].inputCounter));
    MiMC7_0_run(mySubcomponents[cmp_index_ref], ctx);
  }

  {
    FrElement *aux_dest = &signalValues[mySignalStart + 0];
    // load src
    // end load src
    Fr_copy(aux_dest,
            &ctx->signalValues
                 [ctx->componentMemory[mySubcomponents[0]].signalStart + 0]);
  }
  for (uint i = 0; i < 1; i++) {
    uint index_subc = ctx->componentMemory[ctx_index].subcomponents[i];
    release_memory_component(ctx, index_subc);
  }
}

void run(Circom_CalcWit *ctx) {
  Semaphore_1_create(1, 0, ctx, "main", 0);
  Semaphore_1_run(0, ctx);
}
