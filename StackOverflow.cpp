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

static cl::opt<int> level("level", cl::desc("levels to obfuscate"),
                          cl::value_desc("filename"));

namespace
{
class MyPass : public BasicBlockPass
{
  public:
    static char ID;

    MyPass() : BasicBlockPass(ID) {
        srand(time(NULL));
    }

    bool runOnBasicBlock(BasicBlock &BB) override
    {

        bool modified = false;
        int iteration = 0;
        while (iteration++ < level)
        {
            errs() << "Round : " << iteration << "/" << level << "\n";
            for (typename BasicBlock::iterator I = BB.getFirstInsertionPt(), end = BB.end(); I != end; ++I) {

                Instruction &Inst = *I;

                if (!isValidCandidateInstruction(Inst))
                    continue;

                for (size_t i = 0; i < Inst.getNumOperands(); ++i)
                {

                    if (Constant *C = isValidCandidateOperand(Inst.getOperand(i)))
                    {
                        std::stringstream stream;
                        stream << std::hex << C->getUniqueInteger().getLimitedValue();
                        std::string result(stream.str());
                        errs() << "Obfuscating constant: " << result << "\n";
                        if (Value *New_val = obfuscateInt(BB, Inst, C))
                        {

                            Inst.setOperand(i, New_val);
                            modified = true;
                            BB.print(llvm::errs(), true);
                        }
                        else
                        {
                            errs() << "ObfuscateZero: could not rand pick a variable for "
                                      "replacement\n";
                        }
                    }
                }
            }
        }
        return modified;
    }

    // replValue = ~(originalInt ^ key) -1
    Value *obfuscateInt(BasicBlock &BB, Instruction &Inst, Constant *C)
    {

        int key = std::rand();
        int32_t replacedValue = ~(C->getUniqueInteger().getLimitedValue() ^ key);

        Constant *replValue = ConstantInt::get(C->getType(), replacedValue),
                 *keyValue = ConstantInt::get(C->getType(), key),
                 *oneValue = ConstantInt::get(C->getType(), 1);

        IRBuilder<> Builder(&Inst);

        // allocate enough space on the stack to store a 32-bit value. Var name = "AA"
        AllocaInst *varAlloc = Builder.CreateAlloca(C->getType(), nullptr, "AA");

        // Store the key in AA, set "volatile" to true
        Builder.CreateStore(keyValue, varAlloc, false);

        // read the variable "AA"
        LoadInst *loadVar = Builder.CreateLoad(varAlloc, false, "AA");

        // use it
        Value *repl = Builder.CreateXor(replValue, loadVar);
        Value *finValue = Builder.CreateNeg(repl);

        return Builder.CreateSub(finValue, oneValue);
    }

    // only interested in integer values
    Constant *isValidCandidateOperand(Value *V)
    {
        Constant *C;
        if (!(C = dyn_cast<Constant>(V)))
            return nullptr;

        if (!C->getType()->isIntegerTy())
        {
            return nullptr;
        }

        return C;
    }

    bool isValidCandidateInstruction(Instruction &Inst)
    {
        if (isa<GetElementPtrInst>(&Inst))
        {
            errs() << "Ignoring GEP\n";
            return false;
        }
        else if (isa<SwitchInst>(&Inst))
        {
            errs() << "Ignoring Switch\n";
            return false;
        }
        else if (isa<CallInst>(&Inst))
        {
            errs() << "Ignoring Calls\n";
            return false;
        }
        else
        {
            return true;
        }
    }
};

} // namespace

char MyPass::ID = 0;
static RegisterPass<MyPass> X("MyPass", "Obfuscates 1337", true, true);

// register pass for clang use
static void registerMyPassPass(const PassManagerBuilder &,
                               llvm::legacy::PassManagerBase &PM)
{
    PM.add(new MyPass());
}

static RegisterStandardPasses
    RegisterMBAPass(PassManagerBuilder::EP_EnabledOnOptLevel0,
                    registerMyPassPass);
