// Modal open swtich is checked

$('.Switch input[type="checkbox"]').on("change", function (e) {
    if (e.target.checked == true) {
        $("#ActiveModal").modal("show");
    } else {
        $("#InactiveModal").modal("show");
    }
});

// Add New category hide and show

$(document).ready(function () {
    $(".Addcategory").click(function () {
        $("#SelectCategory").css("display", "none");
        $("#CustomCategory").css("display", "block");
    });
});

// Question Answer modal box hide and show

$(document).ready(function () {
    $("#Dropdown").click(function () {
        $("#Options").css("display", "block");
    });
});

$(document).ready(function () {
    $("#Input").click(function () {
        $("#Options").css("display", "none");
    });
});


// Modal Backdrop False

$(document).ready(function () {
    $('.modal').modal({
        backdrop: 'static',
        keyboard: false,
        show: false
    })
});
