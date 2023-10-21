#!/bin/sh

# Check for input file
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

# Add header
cat <<EOT > "$1.new"
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
                ->templateInsId2IOSignalInfoList)[index % get_size_of_io_map()];
  }
};

typedef void (*Circom_TemplateFunction)(uint __cIdx, Circom_CalcWit* __ctx);

//////////////////////////////////////////////////////////////////
/// Generated code from circom compiler below
//////////////////////////////////////////////////////////////////

EOT

# Replace a few things we can't do in cxx
sed -e 's/FrElement\* signalValues/rust::Vec<FrElement> \&signalValues/g' \
    -e 's/std::string/rust::string/g' \
    -e 's/u32\* mySubcomponents/rust::Vec<u32> mySubcomponents/g' \
    -e 's/FrElement\* circuitConstants/rust::Vec<FrElement> \&circuitConstants/g' \
    -e 's/rust::string\* listOfTemplateMessages/rust::Vec<rust::string> \&listOfTemplateMessages/g' \
    -e 's/FrElement expaux\[\([0-9]*\)\];/rust::Vec<FrElement> expaux = create_vec(\1);/g' \
    -e 's/FrElement lvar\[\([0-9]*\)\];/rust::Vec<FrElement> lvar = create_vec(\1);/g' \
    -e 's/PFrElement aux_dest/FrElement \*aux_dest/g' \
    -e 's/subcomponents = new uint\[0\];/subcomponents = rust::Vec<uint32_t>{};/g' \
    -e '/^#include/d' "$1" >> "$1.new"
