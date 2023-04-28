//@author youjeong.Noh
//@category _NEW_

package crashfilter.wrapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class WrapperBasicBlock {

	/* fields */
	protected List<PcodeBlockBasic> successor;
	protected List<PcodeBlockBasic> predecessor;

	protected PcodeBlockBasic basicblock;

	protected WrapperFunction parent;

	/* getter, setter */
	public PcodeBlockBasic getBasicblock() {
		return basicblock;
	}

	public List<PcodeBlockBasic> getSuccessor() {
		return successor;
	}

	public void setSuccessor(List<PcodeBlockBasic> successor) {
		this.successor = successor;
	}

	public List<PcodeBlockBasic> getPredecessor() {
		return predecessor;
	}

	public void setPredecessor(List<PcodeBlockBasic> predecessor) {
		this.predecessor = predecessor;
	}

	public void setBasicblock(PcodeBlockBasic basicblock) {
		this.basicblock = basicblock;
	}

	public WrapperFunction getParent() {
		return parent;
	}

	public void setParent(WrapperFunction parent) {
		this.parent = parent;
	}

	/* constructor */
	private WrapperBasicBlock(WrapperFunction parent, PcodeBlockBasic basicblock) {
		super();
		this.parent = parent;
		this.basicblock = basicblock;

		System.out.println(basicblock.getStart() + ", " + basicblock.getStop());

		// Blocks flowing into this block == predecessor
		List<PcodeBlockBasic> predecessorList = new ArrayList<>();
		for (int i = 0; i < basicblock.getInSize(); i++) {
			predecessorList.add((PcodeBlockBasic) basicblock.getIn(i));
		}
		this.predecessor = predecessorList;

		// Blocks into which this block flows == successor
		List<PcodeBlockBasic> successorList = new ArrayList<>();
		for (int i = 0; i < basicblock.getOutSize(); i++) {
			successorList.add((PcodeBlockBasic) basicblock.getOut(i));
		}
		this.successor = successorList;
	}

	/* functions */

	/* Static Factory Method */
	public static WrapperBasicBlock createBasicBlock(WrapperFunction parent, PcodeBlockBasic basicblock) {
		return new WrapperBasicBlock(parent, basicblock);
	}

	// 다음 노드가 있는지
	public boolean hasSuccessor() {
		if (this.basicblock.getOutSize() == 0) {
			return false;
		}
		return true;
	}

	// 이전 노드가 있는지
	public boolean hasPredecessor() {
		if (this.basicblock.getInSize() == 0) {
			return false;
		}
		return true;
	}

	public List<WrapperBasicBlock> getSuccessors() {

		if (this.basicblock.getOutSize() == 0) {
			return null;
		}

		// 리턴할 BasicBlock 리스트
		List<WrapperBasicBlock> BBList = new ArrayList<>();
		for (int i = 0; i < basicblock.getOutSize(); i++) {
			BBList.add(WrapperBasicBlock.createBasicBlock(parent, (PcodeBlockBasic) basicblock.getOut(i)));
		}
		return BBList;
	}

	public List<WrapperBasicBlock> getPredecessors() {

		if (this.basicblock.getInSize() == 0) {
			return null;
		}

		// 리턴할 BasicBlock 리스트
		List<WrapperBasicBlock> BBList = new ArrayList<>();
		for (int i = 0; i < basicblock.getInSize(); i++) {
			BBList.add(WrapperBasicBlock.createBasicBlock(parent, (PcodeBlockBasic) basicblock.getIn(i)));
		}
		return BBList;
	}

	public List<WrapperPcode> getPcodes() {
		// 리턴할 Pcode 리스트
		List<WrapperPcode> PcodeList = new ArrayList<WrapperPcode>();

		Iterator<PcodeOp> iter = basicblock.getIterator();
		PcodeOp pcode;

		while (iter.hasNext()) {
			pcode = iter.next();
			PcodeList.add(WrapperPcode.createPcode(this, pcode));
		}
		return PcodeList;
	}

}
