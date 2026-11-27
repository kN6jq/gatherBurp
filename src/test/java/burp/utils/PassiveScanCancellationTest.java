package burp.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PassiveScanCancellationTest {
    @Test
    public void cancelInvalidatesRunningTask() {
        PassiveScanCancellation cancellation = new PassiveScanCancellation();
        long generation = cancellation.captureGeneration();

        PassiveScanCancellation.run(cancellation, generation, () -> {
            assertFalse(PassiveScanCancellation.isCancelled());
            cancellation.cancel();
            assertTrue(PassiveScanCancellation.isCancelled());
        });

        assertFalse(PassiveScanCancellation.isCancelled());
    }

    @Test
    public void oldQueuedTaskStaysCancelledAfterNewTaskStarts() {
        PassiveScanCancellation cancellation = new PassiveScanCancellation();
        long oldGeneration = cancellation.captureGeneration();
        cancellation.cancel();
        long newGeneration = cancellation.captureGeneration();

        PassiveScanCancellation.run(cancellation, oldGeneration,
                () -> assertTrue(PassiveScanCancellation.isCancelled()));
        PassiveScanCancellation.run(cancellation, newGeneration,
                () -> assertFalse(PassiveScanCancellation.isCancelled()));
    }
}
