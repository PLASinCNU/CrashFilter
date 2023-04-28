package ghidra.crashfilter.helper;

import java.util.ArrayList;
import java.util.List;

import ghidra.crashfilter.BinNavi.mono.InstructionGraphNode;
import ghidra.crashfilter.BinNavi.mono.interfaces.ILatticeGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class HeapChecker {
	private List<String> allocList;
	private List<Address> heapInstList = new ArrayList<Address>();
	private ILatticeGraph<InstructionGraphNode> graph;
	private static HeapChecker heapChecker;

	public static HeapChecker initHeapChecker(ILatticeGraph<InstructionGraphNode> graph, Function function) {
		heapChecker = new HeapChecker(graph, function);
		return heapChecker;
	}

	public static HeapChecker getHeapChecker() {
		return heapChecker;
	}

	public List<String> getAllocList() {
		return allocList;
	}

	public List<Address> getHeapInstList() {
		return heapInstList;
	}

	public void setGraph(ILatticeGraph<InstructionGraphNode> graph) {
		this.graph = graph;
	}

	public HeapChecker(ILatticeGraph<InstructionGraphNode> graph, Function function) {
		setGraph(graph);

		allocList = new ArrayList<>();
		////// file-
		allocList.add("alloc");
		allocList.add("malloc");
		allocList.add("calloc");
		allocList.add("realloc");

		allocList.add("xalloc");
		allocList.add("xmalloc");
		allocList.add("xcalloc");
		allocList.add("xrealloc");

		allocList.add("HeapAlloc");
		allocList.add("heapalloc");
		allocList.add("farmalloc");
		allocList.add("farcalloc");

		/////////////

		allocList.add("ds: [__imp__malloc]");

		/////////////
		allocList.add("_alloc");
		allocList.add("_malloc");
		allocList.add("_calloc");
		allocList.add("_realloc");

		allocList.add("__heap_alloc");
		allocList.add("__far_malloc");
		allocList.add("__far_calloc");

		//////

		allocList.add("ds:alloc");
		allocList.add("ds:malloc");
		allocList.add("ds:calloc");
		allocList.add("ds:realloc");

		allocList.add("ds:xalloc");
		allocList.add("ds:xmalloc");
		allocList.add("ds:xcalloc");
		allocList.add("ds:xrealloc");

		allocList.add("ds:HeapAlloc");
		allocList.add("ds:heapalloc");
		allocList.add("ds:farmalloc");
		allocList.add("ds:farcalloc");
		////
		findHeapAllocation(function);
	}

	public boolean isAllocateFuction(String str) {
		return allocList.contains(str);
	}

	public boolean eaxHeapMemoryCheck(long reilAddr) {
		// reilAddr /= 0x100;
		for (Address inst : heapInstList) {
			if (inst.getOffset() == reilAddr) {
				return true;
			}
		}
		return false;
	}

	public void findHeapAllocation(Function function) {
		List<InstructionGraphNode> lg = graph.getNodes();
		

		for (InstructionGraphNode ign : lg) {
			PcodeOp pcode = ign.getPcode();
			switch (ign.getPcode().getOpcode()) {
			case PcodeOp.CALL:
			case PcodeOp.CALLIND:
			case PcodeOp.CALLOTHER:
				Varnode op = pcode.getInput(0);
				if(op.isAddress()) {
					Address addr = op.getAddress();
					Function callee = function.getProgram().getListing().getFunctionAt(addr);
					if(this.isAllocateFuction(callee.getName())) {
						this.heapInstList.add(pcode.getSeqnum().getTarget());
					}
				}
				break;
			default:
				break;
			}
		}
	}
}