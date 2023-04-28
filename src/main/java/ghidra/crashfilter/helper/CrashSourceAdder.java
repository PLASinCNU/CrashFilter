package ghidra.crashfilter.helper;

import java.util.*;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;

public class CrashSourceAdder {

	public static Map<Address, InstructionGraphNode> getSrcNAddress(ILatticeGraph<InstructionGraphNode> graph,
			List<Address> crashAddr, InterProcedureMode analysisMode, VariableFinder vf) {

		switch (analysisMode) {
		case NORMAL:
			return getSetOfSrcNAddress(graph, crashAddr);
		case FUNCTIONAnalysis:
			return getSetOfArgumentsNAddress(graph, vf);

		default:
		}
		System.out.println("error : getSrcNAddress() - It is not correct interprocedure Analysis Mode");
		System.exit(-1);
		return null;
	}

	public static List<InstructionGraphNode> getInstructionlist(ILatticeGraph<InstructionGraphNode> graph,
			Long crashAddr) {
		// 지우면 안됨
		List<InstructionGraphNode> originalList = graph.getNodes();
		List<InstructionGraphNode> InstructionGraphNodes = new ArrayList<InstructionGraphNode>();

		for (InstructionGraphNode inst : originalList) {
			long instAddr = inst.getPcode().getParent().getStart().getOffset();

			if (crashAddr == instAddr) {
				InstructionGraphNodes.add(inst);
			}
		}
		return InstructionGraphNodes;
	}

	public static List<InstructionGraphNode> getInstructionlist(ILatticeGraph<InstructionGraphNode> graph,
			Address crashAddr) {
		// 지우면 안됨
		List<InstructionGraphNode> originalList = graph.getNodes();
		List<InstructionGraphNode> InstructionGraphNodes = new ArrayList<InstructionGraphNode>();

		for (InstructionGraphNode inst : originalList) {
			Address instAddr = inst.getAddr();

			if (crashAddr.equals(instAddr)) {
				InstructionGraphNodes.add(inst);
			}
		}
		return InstructionGraphNodes;
	}
	
	public static List<InstructionGraphNode> getInstructions(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr,
			InterProcedureMode interProcedureAnalysisMode, VariableFinder vf) {

		List<InstructionGraphNode> insts = new ArrayList<InstructionGraphNode>();

		switch (interProcedureAnalysisMode) {
		case NORMAL:
			insts.addAll(getInstructionlist(graph, crashAddr));
			return insts;
		case FUNCTIONAnalysis:
			insts.addAll(getArgumentInstruction(graph, vf));

			return insts;

		default:
			return null;
		}
	}

	public static List<InstructionGraphNode> getInstructions(ILatticeGraph<InstructionGraphNode> graph, Address crashAddr,
			InterProcedureMode interProcedureAnalysisMode, VariableFinder vf) {

		List<InstructionGraphNode> insts = new ArrayList<InstructionGraphNode>();

		switch (interProcedureAnalysisMode) {
		case NORMAL:
			insts.addAll(getInstructionlist(graph, crashAddr));
			return insts;
		case FUNCTIONAnalysis:
			insts.addAll(getArgumentInstruction(graph, vf));

			return insts;

		default:
			return null;
		}
	}
	
	private static List<InstructionGraphNode> getArgumentInstruction(ILatticeGraph<InstructionGraphNode> graph,
			VariableFinder vf) {
		// Argument를 use한 native 명령어를 갖고옴
		Set<Instruction> usedArgumentInstructions = vf.getUsedArgumentInstructions();

		List<InstructionGraphNode> insts = new ArrayList<InstructionGraphNode>();

		// 전체 함수의 REIL명령어를 갖고 옴
		List<InstructionGraphNode> originalList = graph.getNodes();

		for (Instruction usedArgumentInst : usedArgumentInstructions) {
			Long usedArgumentInstAddr = usedArgumentInst.getAddress().getOffset();

			for (InstructionGraphNode inst : originalList) {
				long instAddr = inst.getPcode().getParent().getStart().getOffset();

				if (usedArgumentInstAddr == instAddr) {
					insts.add(inst);
				}
			}
		}
		return insts;
	}



	private static Map<Address, InstructionGraphNode> getSetOfArgumentsNAddress(ILatticeGraph<InstructionGraphNode> graph,
			VariableFinder vf) {
		// Argument가 쓰인 Native Instruction을 Reil instruction set으로 바꿔줌
		Set<Instruction> usedArgumentInstructions = vf.getUsedArgumentInstructions();
		Map<Address, InstructionGraphNode> toBeAddedSrcNAddress = new HashMap<Address, InstructionGraphNode>();

		for (InstructionGraphNode ign : graph.getNodes()) {
			for (Instruction inst : usedArgumentInstructions) {
				
				if(ign.getAddr().equals(inst.getAddress()))
					toBeAddedSrcNAddress.put(inst.getAddress(), ign);
			}
		}
		return toBeAddedSrcNAddress;
	}

	private static Map<Address, InstructionGraphNode> getSetOfSrcNAddress(ILatticeGraph<InstructionGraphNode> graph,
			List<Address> crashAddrs) {
		List<InstructionGraphNode> crashSrcNodes = new ArrayList<>();
		Map<Address, InstructionGraphNode> toBeAddedSrcNAddress = new HashMap<Address, InstructionGraphNode>();
		for (InstructionGraphNode ign : graph.getNodes()) {
			for (Address archAddr : crashAddrs) {

				if(ign.getAddr().equals(archAddr) )
					toBeAddedSrcNAddress.put(archAddr, ign);
			}
		}
		return toBeAddedSrcNAddress;
	}
}
