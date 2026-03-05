package io.xpipe.app.pwman;

import io.xpipe.app.comp.base.ButtonComp;
import io.xpipe.app.core.AppCache;
import io.xpipe.app.core.AppI18n;
import io.xpipe.app.core.AppSystemInfo;
import io.xpipe.app.ext.ProcessControlProvider;
import io.xpipe.app.issue.ErrorEventFactory;
import io.xpipe.app.platform.OptionsBuilder;
import io.xpipe.app.process.*;
import io.xpipe.app.terminal.TerminalLaunch;
import io.xpipe.app.util.*;
import io.xpipe.core.InPlaceSecretValue;
import io.xpipe.core.JacksonMapper;
import io.xpipe.core.OsType;

import com.fasterxml.jackson.annotation.JsonTypeName;
import javafx.application.Platform;
import javafx.beans.property.Property;
import javafx.geometry.Insets;
import javafx.scene.layout.Region;
import org.kordamp.ikonli.javafx.FontIcon;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicReference;

@JsonTypeName("bitwarden")
public class BitwardenPasswordManager implements PasswordManager {

    private static ShellControl SHELL;

    private static synchronized ShellControl getOrStartShell() throws Exception {
        if (SHELL == null) {
            SHELL = ProcessControlProvider.get().createLocalProcessControl(true);
            SHELL.start();

            if (moveAppDir()) {
                SHELL.view().unsetEnvironmentVariable("BW_SESSION");
                SHELL.view()
                        .setEnvironmentVariable(
                                "BITWARDENCLI_APPDATA_DIR",
                                AppCache.getBasePath().toString());
            }
        }
        SHELL.start();
        return SHELL;
    }

    @SuppressWarnings("unused")
    public static OptionsBuilder createOptions(Property<BitwardenPasswordManager> p) {
        AtomicReference<Region> button = new AtomicReference<>();
        var testButton = new ButtonComp(AppI18n.observable("sync"), new FontIcon("mdi2r-refresh"), () -> {
            button.get().setDisable(true);
            ThreadHelper.runFailableAsync(() -> {
                sync();
                Platform.runLater(() -> {
                    button.get().setDisable(false);
                });
            });
        });
        testButton.apply(struc -> button.set(struc));
        testButton.padding(new Insets(6, 10, 6, 6));

        return new OptionsBuilder()
                .addComp(testButton);
    }


    private static boolean moveAppDir() throws Exception {
        var path = SHELL.view().findProgram("bw");
        return OsType.ofLocal() != OsType.LINUX
                || path.isEmpty()
                || !path.get().toString().contains("snap");
    }

    private static void sync() throws Exception {
        // Copy existing file if possible to retain configuration. Only once per session
        copyConfigIfNeeded();

        if (!loginOrUnlock()) {
            return;
        }

        getOrStartShell().command(CommandBuilder.of().add("bw", "sync")).execute();
    }

    private static void copyConfigIfNeeded() {
        var cacheDataFile = AppCache.getBasePath().resolve("data.json");
        var def = getDefaultConfigPath();
        if (Files.exists(def)) {
            try {
                var defIsNewer = !Files.exists(cacheDataFile) || Files.getLastModifiedTime(def).compareTo(Files.getLastModifiedTime(cacheDataFile)) > 0;
                if (defIsNewer) {
                    Files.copy(def, cacheDataFile, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException e) {
                ErrorEventFactory.fromThrowable(e).handle();
            }
        }
    }

    private static boolean loginOrUnlock() throws Exception {
        var sc = getOrStartShell();
        var command = sc.command(CommandBuilder.of().add("bw", "get", "item", "xpipe-test", "--nointeraction"));
        var r = command.readStdoutAndStderr();
        if (r[1].contains("You are not logged in")) {
            var script = ShellScript.lines(
                    moveAppDir()
                            ? LocalShell.getDialect()
                            .getSetEnvironmentVariableCommand(
                                    "BITWARDENCLI_APPDATA_DIR",
                                    AppCache.getBasePath().toString())
                            : null,
                    sc.getShellDialect().getEchoCommand("Log in into your Bitwarden account from the CLI:", false),
                    "bw login");
            TerminalLaunch.builder()
                    .title("Bitwarden login")
                    .localScript(script)
                    .logIfEnabled(false)
                    .preferTabs(false)
                    .pauseOnExit(true)
                    .launch();
            return false;
        }

        if (r[1].contains("Vault is locked")) {
            var pw = AskpassAlert.queryRaw("Unlock vault with your Bitwarden master password", null, false);
            if (pw.getSecret() == null) {
                return false;
            }
            var cmd = sc.command(CommandBuilder.of()
                    .add("bw", "unlock", "--raw", "--passwordenv", "BW_PASSWORD")
                    .fixedEnvironment("BW_PASSWORD", pw.getSecret().getSecretValue()));
            cmd.sensitive();
            var out = cmd.readStdoutOrThrow();
            sc.view().setSensitiveEnvironmentVariable("BW_SESSION", out);
        }

        return true;
    }

    @Override
    public synchronized CredentialResult retrieveCredentials(String key) {
        try {
            CommandSupport.isInLocalPathOrThrow("Bitwarden CLI", "bw");
        } catch (Exception e) {
            ErrorEventFactory.fromThrowable(e)
                    .link("https://bitwarden.com/help/cli/#download-and-install")
                    .handle();
            return null;
        }

        // Copy existing file if possible to retain configuration. Only once per session
        copyConfigIfNeeded();

        try {
            if (!loginOrUnlock()) {
                return null;
            }

            var sc = getOrStartShell();
            var cmd =
                    CommandBuilder.of().add("bw", "get", "item").addLiteral(key).add("--nointeraction");
            var json = JacksonMapper.getDefault()
                    .readTree(sc.command(cmd).sensitive().readStdoutOrThrow());
            var login = json.get("login");
            if (login == null) {
                throw ErrorEventFactory.expected(
                        new IllegalArgumentException("No usable login found for item name " + key));
            }

            var user = login.required("username");
            var password = login.required("password");
            return new CredentialResult(user.isNull() ? null : user.asText(), InPlaceSecretValue.of(password.asText()));
        } catch (Exception ex) {
            ErrorEventFactory.fromThrowable(ex).expected().handle();
            return null;
        }
    }

    private static Path getDefaultConfigPath() {
        return switch (OsType.ofLocal()) {
            case OsType.Linux ignored -> {
                if (System.getenv("XDG_CONFIG_HOME") != null) {
                    yield Path.of(System.getenv("XDG_CONFIG_HOME"), "Bitwarden CLI")
                            .resolve("data.json");
                } else {
                    yield AppSystemInfo.ofLinux()
                            .getUserHome()
                            .resolve(".config", "Bitwarden CLI")
                            .resolve("data.json");
                }
            }
            case OsType.MacOs ignored ->
                AppSystemInfo.ofMacOs()
                        .getUserHome()
                        .resolve("Library", "Application Support", "Bitwarden CLI", "data.json");
            case OsType.Windows ignored ->
                AppSystemInfo.ofWindows()
                        .getRoamingAppData()
                        .resolve("Bitwarden CLI")
                        .resolve("data.json");
        };
    }

    @Override
    public String getKeyPlaceholder() {
        return "Item name";
    }

    @Override
    public String getWebsite() {
        return "https://bitwarden.com/";
    }
}
