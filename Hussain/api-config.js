(() => {
    const configuredApiBase = window.PRONTO_API_BASE_URL;
    const isLocalFrontend =
        ["localhost", "127.0.0.1"].includes(window.location.hostname) &&
        window.location.port !== "8000";
    const apiBase = configuredApiBase || (
        isLocalFrontend
            ? `http://${window.location.hostname}:8000`
            : window.location.origin
    );

    window.PRONTO_API_BASE_URL = apiBase.replace(/\/+$/, "");
})();
