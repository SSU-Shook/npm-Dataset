$("button").click(function () {
    var target = $(this).attr("data-target");
    $(target).text($(target).text()); // .text() ensures content is treated as plain text
});
