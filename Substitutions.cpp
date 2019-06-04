
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sstream>

using namespace llvm;

namespace {
class MyPass : public BasicBlockPass {
public:
  static char ID;

  MyPass() : BasicBlockPass(ID) {}

  bool runOnBasicBlock(BasicBlock &BB) override {

    // Not iterating from the beginning to avoid obfuscation of Phi instructions
    // parameters
    bool modified = false;
    for (typename BasicBlock::iterator I = BB.getFirstInsertionPt(),
                                       end = BB.end();
         I != end; ++I) {

      Instruction &Inst = *I;

      if (!isValidCandidateInstruction(Inst))
        continue;

      for (size_t i = 0; i < Inst.getNumOperands(); ++i) {

        if (Constant *C = isValidCandidateOperand(Inst.getOperand(i))) {
          std::stringstream stream;
          stream << std::hex << C->getUniqueInteger().getLimitedValue();
          std::string result(stream.str());
          errs() << "Found an integer: 0x" << result << "\n";

          if (C->getUniqueInteger().getLimitedValue() == 1337) {
            errs() << "Obfuscating 0x6a4abc5b\n";
            if (Value *New_val = obfuscateInt(Inst, C)) {
              Inst.setOperand(i, New_val);
              modified = true;
              //Inst.getOperand(i)->replaceAllUsesWith(New_val);
              errs() << "Replaced with " << New_val << "\n";
            } else {
              errs() << "ObfuscateZero: could not rand pick a variable for "
                        "replacement\n";
            }
          }
        }
      }
    }
    return modified;
  }

  Value *obfuscateInt(Instruction &Inst, Constant *C) {

    srand(time(NULL));
    int key = std::rand();
    int64_t replacedValue = ~(C->getUniqueInteger().getLimitedValue() ^ key);

    Constant *replValue = ConstantInt::get(C->getType(), replacedValue),
             *keyValue = ConstantInt::get(C->getType(), key);

    IRBuilder<> Builder(&Inst);
    Value *repl = Builder.CreateXor(replValue, keyValue);
    Value *finValue = Builder.CreateNeg(repl);

    return Builder.CreateSub(finValue, ConstantInt::get(C->getType(), 1));
  }

  Constant *isValidCandidateOperand(Value *V) {
    Constant *C;
    if (!(C = dyn_cast<Constant>(V)))
      return nullptr;

    if (!C->getType()->isIntegerTy()) {
      return nullptr;
    }

    return C;
  }

  bool isValidCandidateInstruction(Instruction &Inst) {
    if (isa<GetElementPtrInst>(&Inst)) {
      errs() << "Ignoring GEP\n";
      return false;
    } else if (isa<SwitchInst>(&Inst)) {
      errs() << "Ignoring Switch\n";
      return false;
    } else if (isa<CallInst>(&Inst)) {
      errs() << "Ignoring Calls\n";
      return false;
    } else {
      return true;
    }
  }
};

struct Hello : public ModulePass {
  static char ID;
  Hello() : ModulePass(ID) {}

  void handleConstant(GlobalVariable *GV) {

    Constant *c = GV->getInitializer();
    if (c) {
      ConstantDataSequential *cds = dyn_cast<ConstantDataSequential>(c);
      if (cds) {
        if (cds->isString()) {

          errs() << cds->getAsString();
        } else if (cds->isCString()) {
          errs().write_escaped(cds->getAsCString());
        } else {
        }
      }
    }
  }

  bool runOnModule(Module &M) override {
    for (Module::global_iterator I = M.global_begin(), E = M.global_end();
         I != E; ++I) {
      auto GV = dyn_cast<GlobalVariable>(I);
      if (GV->isConstant())
        handleConstant(GV);
    }

    return false;
  }
};
} // namespace

char MyPass::ID = 0;
static RegisterPass<MyPass> X("MyPass", "Obfuscates zeroes", true, false);

char Hello::ID = 0;
static RegisterPass<Hello> Y("Hello", "Find constants", false, false);
// register pass for clang use
static void registerMyPassPass(const PassManagerBuilder &,
                               llvm::legacy::PassManagerBase &PM) {
  PM.add(new MyPass());
  PM.add(new Hello());
}

static RegisterStandardPasses
    RegisterMBAPass(PassManagerBuilder::EP_OptimizerLast, registerMyPassPass);
