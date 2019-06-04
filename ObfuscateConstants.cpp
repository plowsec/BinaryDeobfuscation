#define DEBUG_TYPE "obfuscateconstants"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/User.h"
#include "llvm/Pass.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include <vector>
#include <cstdint>
//#include <Utils.h>
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

STATISTIC(ObfuscatedPHIs, "Number of phis with constants obfuscated");
STATISTIC(ObfuscatedIns, "Number of instructions with constants obfuscated");
STATISTIC(ObfuscatedUses, "Number of constants uses obfuscated");
STATISTIC(ObfuscatedCons, "Number of constants obfuscated");
STATISTIC(ReobfuscatedCons, "Number of constants reobfuscated (obfuscated after obfuscation)");

namespace {
    //static Obf::Probability initialProbability(1,10);
    //static cl::opt< Obf::Probability, false, Obf::ProbabilityParser > reobfuscationProbability ("reobfuscationprobability", cl::desc("Specify the probability of obfuscating again a constant"), cl::value_desc("probability"), cl::Optional, cl::init(initialProbability));
    //The real pass putting it here makes some code simpler
    class DoObfuscateConstants {
        Module &M;
        GlobalVariable *intC;
        IntegerType *intTy;
        PointerType *intTyPtr;
        std::vector<Constant *> intVs;
        unsigned typelength;
        //Obf::CPRNG_AES_CTR *prng;
        inline bool runOnFunction(Function &F) {
            //if no module key found just leave the function alone
            //if (!Obf::CPRNG_AES_CTR::has_obf_key(F))
             //   return false;

            bool rval = false;
            //prng = new Obf::CPRNG_AES_CTR(F,"obfuscateconstants");
            for (Function::iterator B = F.begin(); B != F.end(); B++) {
                for (BasicBlock::iterator I=B->begin(); isa<PHINode>(*I); I++)
                    if(runOnPHI(*cast<PHINode>(&*I))) {
                        ObfuscatedPHIs++;
                        rval = true;
                    }
                for (BasicBlock::iterator I=B->getFirstInsertionPt(); I != B->end(); I++)
                    if(runOnNonPHI(*I)) {
                        ObfuscatedIns++;
                        rval = true;
                    }
            }
            //delete prng;
            return rval;
        }
        /*obfuscate a constant by introducing instructions before the insertionPoint*/
        inline Value * obfuscateConstant (Constant &C, Instruction *insertBefore) {
            /*TODO:As of now we can only obfuscate these*/
            if(isa<ConstantInt>(C)) {
                ObfuscatedCons++;
                ConstantInt &IC = cast<ConstantInt>(C);
                if(IC.getValue().zextOrSelf(typelength) != 0x3CFA685D)  {
                    llvm::errs() << "ouups ignoreing int = " << IC.getValue().zextOrSelf(typelength) << "\n";
                    return nullptr;
                }
                llvm::errs() << "found one \n";
                if (IC.getType()->getBitWidth() <= typelength && 3 == 2/* && prng->get_randomb(1,2)*/) {
                    //Obfuscation technique 1: search for the constant in a vector
                    ConstantInt *Cptr = ConstantInt::get(intTy,intVs.size());
                    intVs.push_back(ConstantInt::get(intTy,IC.getValue().zextOrSelf(typelength)));
                    Value *Vptr = Cptr;
                    //if (reobfuscationProbability.roll(*prng)) {
                      //  ReobfuscatedCons++;
                        //Vptr = obfuscateConstant(*Cptr,insertBefore);
                    //}
                    LoadInst *lic = new LoadInst(intC, "", false, insertBefore);
                    GetElementPtrInst* ptr = GetElementPtrInst::Create(intTy, Vptr, 0, "", insertBefore);
                    //GetElementPtrInst* ptr = GetElementPtrInst::Create(lic, Vptr,"",insertBefore);

                    LoadInst *li = new LoadInst(ptr, "", false, insertBefore);
                    if (IC.getType()->getBitWidth() == typelength)
                        return li;
                    else return new TruncInst(li, IC.getType(), "", insertBefore);
                } else {
                    //Obfuscation technique 2: replace constant by an addition or substraction etc of two other constants
                    ConstantInt *C1 = ConstantInt::get(IC.getType(),31337);
                    //Maybe keep obfuscating the new constant
                    Value *V1 = C1;
                    //if (reobfuscationProbability.rolldiv(*prng,2)) {
                     //   ReobfuscatedCons++;
                      //  V1 = obfuscateConstant(*C1,insertBefore);
                    //}
                    APInt VC2;
                    Instruction::BinaryOps op;
                    int random = 1;
                    //Basic example, we only use Add sub or xor since muls ands and ors are more complicated
                    switch (random) {
                        case 0:
                            VC2 = IC.getValue()-C1->getValue();
                            op=Instruction::Add;
                            assert((VC2 + C1->getValue())==IC.getValue());
                            break;
                        case 1:
                            VC2 = IC.getValue()+C1->getValue();
                            op=Instruction::Sub;
                            assert((VC2 - C1->getValue())==IC.getValue());
                            break;
                        case 2:
                            VC2 = IC.getValue()^C1->getValue();
                            op=Instruction::Xor;
                            assert((VC2 ^ C1->getValue())==IC.getValue());
                            break;
                    }
                    ConstantInt *C2 = cast<ConstantInt>(ConstantInt::get(IC.getType(),VC2));
                    Value *V2 = C2;
                    //Maybe keep obfuscating the new constant
                    //if (reobfuscationProbability.rolldiv(*prng,2)) {
                      //  ReobfuscatedCons++;
                       // V2 = obfuscateConstant(*C2,insertBefore);
                    //}
                    llvm::errs() << "YJIENFIAJD NI\n";
                    return BinaryOperator::Create(op, V2, V1, "", insertBefore);
                }
                //TODO: obfuscation technique 3: use a formula returning the constant over some previous value 
            }
            return &C;
        }
        //Obfuscate an Use if it s a constant (and we want to do so)
        //Returns true if the use was modified
        inline bool obfuscateUse(Use &U, Instruction *insertBefore) {
            Constant *C = dyn_cast<Constant>(U.get());
            if (C == 0) return false;//Not a constant
            Value *NC = obfuscateConstant(*C, insertBefore);
            if (NC == C || NC == 0) return false; //The constant wasn't modified
            ObfuscatedUses++;
            U.set(NC);
            return true;
        }
        /* Run on a phi instruction */
        inline bool runOnPHI(PHINode &phi) {
            bool rval = false;
            /*If a constant is found the value must be calculated on the phy node bringing us here*/
            for (User::op_iterator O = phi.op_begin(); O != phi.op_end(); O++) {
                rval |= obfuscateUse(*O,phi.getIncomingBlock(*O)->getTerminator());
            }
            return rval;
        }
        /* Run on a non phi instruction*/
        inline bool runOnNonPHI(Instruction &I) {
            bool rval=false;
            /*Check only value (arg 1)*/
            if(isa<SwitchInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I);
            /*Check only vectors (args 1 and 2)*/
            if(isa<ShuffleVectorInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I) | obfuscateUse(I.getOperandUse(1),&I);
            /*Check only struct and value (args 1 and 2)*/
            if(isa<InsertValueInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I) | obfuscateUse(I.getOperandUse(1),&I);
            /*Check only struct (arg 1)*/
            if(isa<ExtractValueInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I);
            /*Check only NumElements (arg 1)*/
            if(isa<AllocaInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I);
            /*Ignore alignment*/
            if(isa<LoadInst>(I))
                return obfuscateUse(I.getOperandUse(0),&I);
            /*TODO: Ignore constants in structs*/
            if(isa<GetElementPtrInst>(I))
                return false;
            /*landingpads???*/
            /*Intrinsics???*/
            /*Check all the values*/
            for (User::op_iterator O = I.op_begin(); O != I.op_end(); O++) {
                rval |= obfuscateUse(*O,&I);
            }
            return rval;
        }
    public:
        DoObfuscateConstants(Module &M) : M(M) {
        }
        bool run() {
            //TODO:This should depend on the target type
            typelength=64;
            intTy = IntegerType::get(M.getContext(), typelength);
            intTyPtr = PointerType::get(intTy, 0);
 
            intC = new GlobalVariable(M,intTyPtr,false,GlobalVariable::PrivateLinkage,0,".data");
            bool rval = false;
            for (Module::iterator F = M.begin(); F != M.end(); F++) {
                if (F->empty())
                    continue;
                rval |= runOnFunction(*F);
            }
            ArrayType* ArrayTy = ArrayType::get(intTy, intVs.size());
            GlobalVariable *arrC = new GlobalVariable(M,ArrayTy,false,GlobalVariable::PrivateLinkage,ConstantArray::get(ArrayTy, intVs));
            //intC->setInitializer(ConstantExpr::getGetElementPtr(ArrayTy, arrC, std::vector<Constant*>(2,ConstantInt::get(intTy,0))));
            Constant *init = llvm::ConstantArray::get(ArrayTy, std::vector<Constant*>(2,ConstantInt::get(intTy,0)));
            intC->setInitializer(init);

            //intC->setInitializer(Constant::getNullValue(ArrayType::get(Type::getInt32Ty(M.getContext()), 12))); 
            //ConstantExpr::getGetElementPtr(intTy, std::vector<Constant*>(2,ConstantInt::get(intTy,0)), )
            return rval;
        }
    };
    //Saddly we can't keep global state if using the FunctionPass :(
    struct ObfuscateConstants : public ModulePass {
        static char ID; // Pass identification, replacement for typeid
        ObfuscateConstants() : ModulePass(ID) {}
        virtual bool runOnModule(Module &M){
            DoObfuscateConstants obc(M);
            return obc.run();
        }
    };
}

char ObfuscateConstants::ID = 0;
static RegisterPass<ObfuscateConstants> X("obfuscateconstants", "Obfuscate the code constants by converting them into mathematical operations and dereferences from a vector");
