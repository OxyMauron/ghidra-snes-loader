package snesloader;

import java.util.List;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import snesloader.RomReader.RomChunk;

public class HiRomLoader implements RomInfoProvider {
	public static final long SNES_HEADER_OFFSET = 0xFFC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x1_0000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace busSpace = prog.getAddressFactory().getDefaultAddressSpace();

		RomReader reader = new RomReader(romInfo, provider);
		for (RomChunk romChunk : reader) {
			List<Address> busAddresses = getBusAddressesForRomChunk(romChunk, busSpace);

			String primaryBlockName = getRomChunkPrimaryName(romChunk);
			Address primaryAddress = busAddresses.remove(0);
			try {
				MemoryBlockUtils.createInitializedBlock(prog, false, primaryBlockName, primaryAddress,
						romChunk.getInputStream(), romChunk.getLength(), "", provider.getAbsolutePath(), true, false,
						true, log, monitor);
			} catch (AddressOverflowException e) {
				throw new IllegalStateException("Invalid address range specified: start:" + primaryAddress + ", length:"
						+ romChunk.getLength() + " - end address exceeds address space boundary!");
			}
		}
		
		CreateWRAM(prog, log);

		// throw new UnsupportedOperationException("Loading a HI_ROM format is not
		// implemented yet.");

		return true;
	}

	private static List<Address> getBusAddressesForRomChunk(RomChunk chunk, AddressSpace space) {
		var busAddresses = new ArrayList<Address>();
		long chunkStartAddress = chunk.getRomAddresses().left;

		busAddresses.add(space.getAddress(chunkStartAddress + 0xc0_0000));

		return busAddresses;
	}

	private static String getRomChunkPrimaryName(RomChunk chunk) {
		long leftAddr = chunk.getRomAddresses().left;
		int leftBank = (int) ((leftAddr & 0xff_0000) >> 16);
		int leftSmall = (int) (leftAddr & 0xffff);

		long rightAddr = chunk.getRomAddresses().right;
		int rightBank = (int) ((rightAddr & 0xff_0000) >> 16);
		int rightSmall = (int) (rightAddr & 0xffff);

		return String.format("rom_%02x:%04x-%02x:%04x", leftBank, leftSmall, rightBank, rightSmall);
	}

	public static void CreateWRAM(Program prog, MessageLog log)  {
		
		MemoryBlockUtils.createUninitializedBlock(prog, false, "WRAM $7E:0000 - WRAM $7E:FFFF", prog.getAddressFactory().getDefaultAddressSpace().getAddress((long)0x7e_0000), 0x1_0000, "", "", true, true, true, log);
		MemoryBlockUtils.createUninitializedBlock(prog, false, "WRAM $7F:0000 - WRAM $7F:FFFF", prog.getAddressFactory().getDefaultAddressSpace().getAddress((long)0x7f_0000), 0x1_0000, "", "", true, true, true, log);
	}

	@Override
	public long getSnesHeaderOffset() {
		return SNES_HEADER_OFFSET;
	}

	@Override
	public long getMaxRomSize() {
		return MAX_ROM_SIZE;
	}

	@Override
	public long getChunkSize() {
		return ROM_CHUNK_SIZE;
	}

	@Override
	public RomLoader getLoaderFunction() {
		return HiRomLoader::load;
	}
	
}
