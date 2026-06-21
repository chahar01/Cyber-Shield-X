(function () {
    let deferredPrompt = null;
    let installButton = null;

    function setInstallButtonVisible(isVisible) {
        if (!installButton) {
            return;
        }

        installButton.hidden = !isVisible;
    }

    window.addEventListener("beforeinstallprompt", function (event) {
        event.preventDefault();
        deferredPrompt = event;
        setInstallButtonVisible(true);
    });

    window.addEventListener("appinstalled", function () {
        deferredPrompt = null;
        setInstallButtonVisible(false);
    });

    window.addEventListener("DOMContentLoaded", function () {
        installButton = document.querySelector("[data-install-app]");
        if (!installButton) {
            return;
        }

        installButton.addEventListener("click", function () {
            if (!deferredPrompt) {
                return;
            }

            deferredPrompt.prompt();
            deferredPrompt.userChoice.finally(function () {
                deferredPrompt = null;
                setInstallButtonVisible(false);
            });
        });

        setInstallButtonVisible(Boolean(deferredPrompt));
    });

    if (!("serviceWorker" in navigator)) {
        return;
    }

    window.addEventListener("load", function () {
        navigator.serviceWorker.register("/static/service-worker.js", {
            scope: "/"
        }).catch(function () {
            // Installation should never block the web experience.
        });
    });
})();
