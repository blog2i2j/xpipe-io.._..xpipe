package io.xpipe.app.browser.menu;

import io.xpipe.app.browser.file.BrowserEntry;
import io.xpipe.app.browser.file.BrowserFileSystemTabModel;

import java.util.List;

public interface BrowserApplicationPathMenuProvider extends BrowserMenuItemProvider {

    String getExecutable();

    @Override
    default void init(BrowserFileSystemTabModel model) {
        // Cache result for later calls
        model.getCache().isApplicationInPath(getExecutable());
    }

    @Override
    default boolean isActive(BrowserFileSystemTabModel model, List<BrowserEntry> entries) {
        return model.getCache().isApplicationInPath(getExecutable());
    }
}
