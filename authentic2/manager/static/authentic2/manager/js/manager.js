function displayPopup(event)
{
    var $anchor = $(this);
    var url = $anchor.attr('href');
    var selector = $anchor.data('selector') || 'form';

    function ajaxform_submit (data, status, xhr, form) {
        if ('location' in data) {
            var location = $.url(data.location);
            var href = $.url(window.location.href);
            if (location.attr('protocol') == href.attr('protocol') &&
                location.attr('host') == href.attr('host') &&
                location.attr('relative') == href.attr('relative')) {
                var e = $.Event('popup-success');
                $anchor.trigger(e);
                if (! e.isDefaultPrevented()) {
                  window.location.reload(true);
                }
            }
            // set anchor if it changed
            window.location = data.location;
        } else {
            var html = data.content;
            $(form).empty().append($(html).find(selector).children());
            $(form).find('.buttons').hide();
        }
    }

    $.ajax({
        url: url,
        success: function(html) {
            var is_json = typeof html != 'string';
            if (is_json) {
                var html = html.content;
            } else {
                var html = html;
            }
            var form = $(html).find(selector);
            var title = $(html).find('#appbar h2').text();
            var dialog = $(form).dialog({modal: true, 'title': title, width: 'auto'});
            var buttons = Array();
            if (! form.prop('action')) {
                form.prop('action', url);
            }
            $(dialog).find('.buttons').hide();
            $(html).find('.buttons button, .buttons a').each(function(idx, elem) {
                var button = Object();
                button.text = $(elem).text();
                if ($(elem).hasClass('cancel')) {
                    button.click = function() { dialog.dialog('destroy'); return false; };
                } else {
                    button.click = function() { form.find('button').click(); return false; };
                }
                if ($(elem).hasClass('submit-button')) {
                    button.class = 'submit-button';
                } else if ($(elem).hasClass('delete-button')) {
                    button.class = 'delete-button';
                }
                buttons.push(button);
            });
            buttons.reverse();
            $(dialog).dialog('option', 'buttons', buttons);
            if ($(dialog).find('input:visible').length) {
                $(dialog).find('input:visible')[0].focus();
            }
            if (is_json && $.fn.url != undefined && $.fn.ajaxForm != undefined) {
                $(form).ajaxForm({success: ajaxform_submit});
            }
            return false;
        }
    });
    return false;
}

$(function() {
    $('a[rel=popup]').click(displayPopup);
});
