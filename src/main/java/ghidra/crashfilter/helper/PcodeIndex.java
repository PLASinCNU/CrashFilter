package ghidra.crashfilter.helper;

public enum PcodeIndex {
	COPY(1),
	LOAD(2),
	STORE(3),
	BRANCH(4),
	CBRANCH(5),
	BRANCHIND(6),
	CALL(7),
	CALLIND(8),
	USERDEFINED(9),
	RETURN(10),
	PIECE(11),
	SUBPIECE(12),
	INT_EQUAL(13),
	INT_NOTEQUAL(14),
	INT_LESS(15),
	INT_SLESS(16),
	INT_LESSEQUAL(17),
	INT_SLESSEQUAL(18),
	INT_ZEXT(19),
	INT_SEXT(20),
	INT_ADD(21),
	INT_SUB(22),
	INT_CARRY(23),
	INT_SCARRY(24),
	INT_SBORROW(25),
	INT_2COMP(26),
	INT_NEGATE(27),
	INT_XOR(28),
	INT_AND(29),
	INT_OR(30),
	INT_LEFT(31),
	INT_RIGHT(32),
	INT_SRIGHT(33),
	INT_MULT(34),
	INT_DIV(35),
	INT_REM(36),
	INT_SDIV(37),
	INT_SREM(38),
	BOOL_NEGATE(39),
	BOOL_XOR(40),
	BOOL_AND(41),
	BOOL_OR(42),
	FLOAT_EQUAL(43),
	FLOAT_NOTEQUAL(44),
	FLOAT_LESS(45),
	FLOAT_LESSEQUAL(46),
	FLOAT_ADD(47),
	FLOAT_SUB(48),
	FLOAT_MULT(49),
	FLOAT_DIV(50),
	FLOAT_NEG(51),
	FLOAT_ABS(52),
	FLOAT_SQRT(53),
	FLOAT_CEIL(54),
	FLOAT_FLOOR(55),
	FLOAT_ROUND(56),
	FLOAT_NAN(57),
	INT2FLOAT(58),
	FLOAT2FLOAT(59),
	TRUNC(60),
	CPOOLREF(61),
	NEW(62);

	private final int index;

	private PcodeIndex(int index) {
		this.index = index;
	}

	public int getIndex() {
		return this.index;
	}
}
