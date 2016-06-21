$(function () {
    $('.list-widget').sortable({handle: '.handle'});
    $('.list-widget-add-button').on('click', function (ev) {
        var template_id = $(ev.target).data('template-id');
        var needle = $(ev.target).data('needle');
        var $ol = $(ev.target).prevAll('ol');
        var template = $ol.data('template');
        var count_id = template_id.replace(needle, 'count');
        var $count = $('#' + count_id);
        var count = parseInt($count.val());
        $count.val(count+1);
        $(template.replace(needle, count.toString(), 'g')).appendTo($ol);
    });
});
