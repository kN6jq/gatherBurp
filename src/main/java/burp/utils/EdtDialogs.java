package burp.utils;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/** EDT 弹窗执行器：扫描线程被中断时撤销待执行弹窗并关闭已打开的模态窗口。 */
public final class EdtDialogs {
    private EdtDialogs() {
    }

    public static String showInput(Component parent, Object message, String title, int messageType,
                                   Icon icon, Object[] options, Object initialValue) {
        Object value = show(parent, title, () -> {
            JOptionPane pane = new JOptionPane(message, messageType,
                    JOptionPane.OK_CANCEL_OPTION, icon, null, initialValue);
            pane.setWantsInput(true);
            pane.setSelectionValues(options);
            pane.setInitialSelectionValue(initialValue);
            return pane;
        });
        return value == null ? null : String.valueOf(value);
    }

    public static boolean showMessage(Component parent, Object message, String title, int messageType) {
        return show(parent, title, () -> new JOptionPane(message, messageType, JOptionPane.DEFAULT_OPTION)) != null;
    }

    private static Object show(Component parent, String title, Supplier<JOptionPane> paneSupplier) {
        if (SwingUtilities.isEventDispatchThread()) {
            JOptionPane pane = paneSupplier.get();
            JDialog dialog = pane.createDialog(parent, title);
            dialog.setVisible(true);
            dialog.dispose();
            return pane.getValue();
        }

        AtomicBoolean cancelled = new AtomicBoolean(false);
        AtomicReference<JDialog> dialogRef = new AtomicReference<>();
        Object[] value = new Object[1];
        Runnable task = () -> {
            JOptionPane pane = paneSupplier.get();
            JDialog dialog = pane.createDialog(parent, title);
            dialogRef.set(dialog);
            if (cancelled.get()) {
                dialog.dispose();
                return;
            }
            dialog.setVisible(true);
            value[0] = pane.getValue();
            dialog.dispose();
        };

        try {
            SwingUtilities.invokeAndWait(task);
        } catch (InterruptedException e) {
            cancelled.set(true);
            JDialog dialog = dialogRef.get();
            if (dialog != null) {
                SwingUtilities.invokeLater(dialog::dispose);
            }
            Thread.currentThread().interrupt();
            return null;
        } catch (InvocationTargetException e) {
            if (Utils.stderr != null) {
                Utils.stderr.println("EDT dialog failed: " + e.getCause());
            }
            return null;
        }
        return value[0];
    }
}
