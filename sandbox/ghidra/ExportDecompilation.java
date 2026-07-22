// Headless-only result exporter used by ctf-ghidra-headless.
import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportDecompilation extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected one output path");
        }
        File output = new File(args[0]);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("unable to initialize decompiler");
        }
        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            writer.printf("/* program: %s */%n", currentProgram.getName());
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                writer.printf("%n/* %s @ %s */%n", function.getName(), function.getEntryPoint());
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    writer.println(result.getDecompiledFunction().getC());
                } else {
                    writer.printf("/* decompilation unavailable: %s */%n", result.getErrorMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
