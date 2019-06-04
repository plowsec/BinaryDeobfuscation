#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <time.h>

#include <unordered_set>
using namespace llvm;

static cl::opt<int> level("ad-level", cl::desc("levels to obfuscate"),
                          cl::value_desc("filename"));

namespace
{
struct AntiDbg : public FunctionPass
{
    static char ID;
    AntiDbg() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override
    {
        srand(time(0));

        errs().write_escaped(F.getName()) << '\n';
        if (F.getName().equals("antidbg") || F.getName().equals("compare") || F.getName().equals("YieldExecution") || F.getName().equals("YieldExecution2") || F.getName().equals("DebuggerPresent") || F.getName().equals("secure_string") || F.getName().equals("tohex") || F.getName().equals("decrypt") || F.getName().equals("chr2dec"))
        {
            errs() << "Skipped " << F.getName() << "\n";
            return false;
        }

        for (Function::iterator bb = F.begin(); bb != F.end(); ++bb)
        {
            for (BasicBlock::iterator I = bb->begin(); I != bb->end(); ++I)
            {
                int r = rand() % 6 + 1;
                if(r != 4)
                    continue;
                
                Instruction &Inst = *I;
                //BasicBlock *basicBlock = dyn_cast<BasicBlock>(I);
                IRBuilder<> Builder(&Inst);

                llvm::Type *VoidTy = llvm::IntegerType::getVoidTy(F.getContext());

                llvm::FunctionType *AsmTy = llvm::FunctionType::get(VoidTy, false);
                // Declare it in the current module (or get a reference to it)
                llvm::Constant *function = F.getParent()->getOrInsertFunction("antidbg", AsmTy);

                Builder.CreateCall(function, None);
                break;
            }
        }

        return true;
    }
};
} // namespace

char AntiDbg::ID = 0;
static RegisterPass<AntiDbg> X("antidbg", "antidbg");