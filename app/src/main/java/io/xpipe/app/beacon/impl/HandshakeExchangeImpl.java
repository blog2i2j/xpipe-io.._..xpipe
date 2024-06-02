package io.xpipe.app.beacon.impl;


import com.sun.net.httpserver.HttpExchange;
import io.xpipe.app.beacon.AppBeaconServer;
import io.xpipe.app.beacon.BeaconSession;
import io.xpipe.app.prefs.AppPrefs;
import io.xpipe.beacon.BeaconAuthMethod;
import io.xpipe.beacon.BeaconClientException;
import io.xpipe.beacon.BeaconServerException;
import io.xpipe.beacon.api.HandshakeExchange;

import java.io.IOException;
import java.util.UUID;

public class HandshakeExchangeImpl extends HandshakeExchange {

    @Override
    public Object handle(HttpExchange exchange, Request body) throws IOException, BeaconClientException, BeaconServerException {
        if (!checkAuth(body.getAuth())) {
            throw new BeaconClientException("Authentication failed");
        }

        var session = new BeaconSession(body.getClient(), UUID.randomUUID().toString());
        AppBeaconServer.get().addSession(session);
        return Response.builder().token(session.getToken()).build();
    }

    private boolean checkAuth(BeaconAuthMethod authMethod) {
        if (authMethod instanceof BeaconAuthMethod.Local local) {
            var c = local.getAuthFileContent().trim();
            return AppBeaconServer.get().getLocalAuthSecret().equals(c);
        }

        if (authMethod instanceof BeaconAuthMethod.ApiKey key) {
            var c = key.getKey().trim();
            return AppPrefs.get().apiKey().get().equals(c);
        }

        return false;
    }
}
