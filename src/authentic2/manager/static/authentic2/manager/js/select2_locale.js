(function ($) {
    $.extend($.fn.select2.defaults, {
         formatMatches: function (matches) {
             if (matches === 1) {
                 return gettext("One result is available, press enter to select it.");
             }
             return interpolate(
                     gettext("%s results are available, use up and down arrow keys to navigate."),
                     [matches]);
         },
         formatNoMatches: function () {
             return gettext("No matches found");
         },
         formatAjaxError: function (jqXHR, textStatus, errorThrown) {
             return gettext("Loading failed");
         },
         formatInputTooShort: function (input, min) {
             var n = min - input.length;
             return interpolate(
                     ngettext("Please enter %s or more character", "Please enter %s or more characters", n),
                     [n]);
         },
         formatInputTooLong: function (input, max) {
             var n = input.length - max;
             return interpolate(
                     ngettext("Please delete %s character", "Please delete %s characters", n),
                     [n]);
         },
         formatSelectionTooBig: function (limit) {
             return interpolate(
                     ngettext("You can only select %s item", "You can only select %s items", limit),
                     [limit]);
         },
         formatLoadMore: function (pageNumber) {
             return gettext("Loading more results…");
         },
         formatSearching: function () {
             return gettext("Searching…");
         }
    });
})(jQuery)
