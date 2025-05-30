package io.xpipe.ext.base.browser;

import io.xpipe.app.browser.action.BrowserLeafAction;
import io.xpipe.app.browser.file.BrowserEntry;
import io.xpipe.app.browser.file.BrowserFileOpener;
import io.xpipe.app.browser.file.BrowserFileSystemTabModel;
import io.xpipe.app.core.AppI18n;
import io.xpipe.core.process.OsType;
import io.xpipe.core.store.FileKind;

import javafx.beans.value.ObservableValue;
import javafx.scene.Node;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;

import org.kordamp.ikonli.javafx.FontIcon;

import java.util.List;

public class OpenFileWithAction implements BrowserLeafAction {

    @Override
    public void execute(BrowserFileSystemTabModel model, List<BrowserEntry> entries) {
        var e = entries.getFirst();
        BrowserFileOpener.openWithAnyApplication(model, e.getRawFileEntry());
    }

    @Override
    public Node getIcon(BrowserFileSystemTabModel model, List<BrowserEntry> entries) {
        return new FontIcon("mdi2b-book-open-page-variant-outline");
    }

    @Override
    public Category getCategory() {
        return Category.OPEN;
    }

    @Override
    public KeyCombination getShortcut() {
        return new KeyCodeCombination(KeyCode.ENTER, KeyCombination.SHIFT_DOWN);
    }

    @Override
    public ObservableValue<String> getName(BrowserFileSystemTabModel model, List<BrowserEntry> entries) {
        return AppI18n.observable("openFileWith");
    }

    @Override
    public boolean isApplicable(BrowserFileSystemTabModel model, List<BrowserEntry> entries) {
        return OsType.getLocal().equals(OsType.WINDOWS)
                && entries.size() == 1
                && entries.stream().allMatch(entry -> entry.getRawFileEntry().getKind() == FileKind.FILE);
    }
}
