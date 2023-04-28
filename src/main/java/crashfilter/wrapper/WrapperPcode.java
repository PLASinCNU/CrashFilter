//@author youjeong.Noh
//@category _NEW_

package crashfilter.wrapper;

import ghidra.program.model.pcode.PcodeOp;

public class WrapperPcode {

	/* fields */
	protected WrapperBasicBlock parent;

	protected PcodeOp pcode;

	/* getter, setter */
	public WrapperBasicBlock getParent() {
		return parent;
	}

	public void setParent(WrapperBasicBlock parent) {
		this.parent = parent;
	}

	public PcodeOp getPcode() {
		return pcode;
	}

	public void setPcode(PcodeOp pcode) {
		this.pcode = pcode;
	}

	/* constructor */
	private WrapperPcode(WrapperBasicBlock parent, PcodeOp pcode) {
		super();
		this.parent = parent;
		this.pcode = pcode;
	}

	/* functions */

	/* Static Factory Method */
	public static WrapperPcode createPcode(WrapperBasicBlock parent, PcodeOp pcode) {
		return new WrapperPcode(parent, pcode);
	}

}
