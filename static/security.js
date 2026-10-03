(function () {

    "use strict";

    // Disable right-click
    document.addEventListener(
        "contextmenu",
        function (event) {
            event.preventDefault();
        }
    );

    // Block common keyboard shortcuts
    document.addEventListener(
        "keydown",
        function (event) {

            const key = event.key.toUpperCase();

            // F12
            if (event.key === "F12") {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }

            // Ctrl + Shift + I
            if (
                event.ctrlKey &&
                event.shiftKey &&
                key === "I"
            ) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }

            // Ctrl + Shift + J
            if (
                event.ctrlKey &&
                event.shiftKey &&
                key === "J"
            ) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }

            // Ctrl + Shift + C
            if (
                event.ctrlKey &&
                event.shiftKey &&
                key === "C"
            ) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }

            // Ctrl + U
            if (
                event.ctrlKey &&
                key === "U"
            ) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }

        },
        true
    );

})();
