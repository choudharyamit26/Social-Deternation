
// for full calender
//  document.addEventListener('DOMContentLoaded', function() {
//    var calendarEl = document.getElementById('calendar1');
//
//    var calendar = new FullCalendar.Calendar(calendarEl, {
//      plugins: [ 'interaction', 'dayGrid', 'timeGrid' ],
//      timeZone: 'UTC',
//      defaultView: 'dayGridMonth',
//      header: {
//        left: 'prev,next today',
//        center: 'title',
//        right: 'dayGridMonth,timeGridWeek,timeGridDay'
//      }
//      events: [
//                    {% for event in events %}
//                        {
//                            title: "{{ event.name}}",
//                            start: '{{ event.start|date:"Y-m-d" }}',
//                            end: '{{ event.end|date:"Y-m-d" }}',
//                            id: '{{ event.id }}',
//                        },
//                    {% endfor %}
//                ],
//      editable: true,
//
//      // JSON FEED INSTRUCTIONS
//      //
//      // 1. Open a new browser tab. Go to codepen.io
//      //
//      // 2. Create a new pen (Create > New Pen)
//      //
//      // 3. Paste your JSON into the JS pane
//      //
//      // 4. Hit the "Save" button
//      //
//      // 5. The page's URL will change. It will look like this:
//      //    https://codepen.io/anon/pen/eWPBOx
//      //
//      // 6. Append ".js" to it. Will become like this:
//      //    https://codepen.io/anon/pen/eWPBOx.js
//      //
//      // 7. Paste this URL below.
//      //
//      events: 'https://codepen.io/SSTWebmaster/pen/OGYByJ.js'
//
//      // 8. Then, enter a date for defaultDate that best displays your events.
//      //
//
//    });
//
//    calendar.render();
//  });

// full calender end 


$(window).on('scroll', function () {
  if ($(window).scrollTop() >= 78) {
    $('.header').addClass('fixedHeader');
  } else {
    $('.header').removeClass('fixedHeader');
  }
});

$(document).on('click', '.signUpby ul li', function () {
  $('.signUpby ul li').removeClass('active');
  $(this).addClass('active');
});

$(document).on('click', '.signUpby ul li.first', function () {
  $('.formByMail').addClass('active');
  $('.formByNumber').removeClass('active');
});
$(document).on('click', '.signUpby ul li.second', function () {
  $('.formByNumber').addClass('active');
  $('.formByMail').removeClass('active');
});

// my-profile image uploader
function readFile(input) {
  if (input.files && input.files[0]) {
    var reader = new FileReader();

    reader.onload = function (e) {
      var htmlPreview =
        '<img width="200" src="' + e.target.result + '" />' +
        '<p>' + input.files[0].name + '</p>';
      var wrapperZone = $(input).parent();
      var previewZone = $(input).parent().parent().find('.preview-zone');
      var boxZone = $(input).parent().parent().find('.preview-zone').find('.box').find('.box-body');

      wrapperZone.removeClass('dragover');
      previewZone.removeClass('hidden');
      boxZone.empty();
      boxZone.append(htmlPreview);
    };

    reader.readAsDataURL(input.files[0]);
  }
}

function reset(e) {
  e.wrap('<form>').closest('form').get(0).reset();
  e.unwrap();
}

$(".dropzone").change(function () {
  readFile(this);
});

$('.dropzone-wrapper').on('dragover', function (e) {
  e.preventDefault();
  e.stopPropagation();
  $(this).addClass('dragover');
});

$('.dropzone-wrapper').on('dragleave', function (e) {
  e.preventDefault();
  e.stopPropagation();
  $(this).removeClass('dragover');
});

$('.remove-preview').on('click', function () {
  var boxZone = $(this).parents('.preview-zone').find('.box-body');
  var previewZone = $(this).parents('.preview-zone');
  var dropzone = $(this).parents('.form-group').find('.dropzone');
  boxZone.empty();
  previewZone.addClass('hidden');
  reset(dropzone);
});
// my-profile image uploader end

$(document).on('click', '.topHeader a', function () {
  $('.topHead').slideUp();
});




$(document).on('click', '.availModal li a', function () {
  // $('.availModal li a').removeClass('active');
  $(this).addClass('active');
});
$(document).on('click', '.notification', function () {
  $('.notificationDet').slideDown();
  // alert('okk');
});

document.addEventListener("mousedown", function (event) {
  if (event.target.closest(".notificationDet,.notification"))
    return;
  $('.notificationDet').slideUp();
});


$(document).on('click', '.video', function () {
  $('.call1').animate({ 'top': '0' });
  $('.call2').animate({ 'top': '-100%' });
});
$(document).on('click', '.cutcall', function () {
  $('.call1').animate({ 'top': '-100%' });
  $('.returnCallAudio').slideUp();
});
$(document).on('click', '.vidio', function () {
  $('.call2').animate({ 'top': '0' });
  $('.call1').animate({ 'top': '-100%' });
});
$(document).on('click', '.cutcall', function () {
  $('.call2').animate({ 'top': '-100%' });
});
$(document).on('click', '.welcomeBord a', function () {
  $('.welcomeBord').slideUp();
});
$(document).on('click', '.returnCallAudio', function () {
  $('.call1').animate({ 'top': '0' });
  $('.returnCallAudio').slideUp();
});
$(document).on('click', '.message', function () {
  $('.call1').animate({ 'top': '-100%' });
  $('.returnCallAudio').slideDown();
  // alert('okk');
});
$(document).on('click', '.returnCallVideo', function () {
  $('.call2').animate({ 'top': '0' });
  $('.returnCallVideo').slideUp();
});
$(document).on('click', '.message2', function () {
  $('.call2').animate({ 'top': '-100%' });
  $('.returnCallVideo').slideDown();
  // alert('okk');
});


$(document).on('click', '.radio label', function () {
  $('.radio label').removeClass('active');
  $(this).addClass('active');
});

$(document).on('click', '.popnext', function () {
  if ($('.radio-label.single').hasClass('active')) {
    $('#singleModal').show();
  }
});
$(document).on('click', '.popnext', function () {
  if ($('.radio-label.multiple').hasClass('active')) {
    $('#multiModal').show();
  }
});

$(document).on('click', '.closee', function () {
  $('#singleModal,#multiModal').hide();
});

$(document).ready(function () {
  $(".radio-label.single.amitPy").click(function () {
    $(this).toggleClass("active");
  });
});



$(document).on('click', '.radio-label.single', function () {
  $('.singleId ').hide();
});

$(document).on('click', '.radio-label.single', function () {
  $('td.fc-today').removeClass('active'),
  $('.calender').removeClass('multidate');
  $('.calender').addClass('singledate');
});
$(document).on('click', '.radio-label.multiple', function () {
  $('td.fc-day-top').removeClass('fc-today'),
    $('.calender').removeClass('singledate');
  $('.calender').addClass('multidate');
});

$(document).on('click', '.singledate td.fc-future', function () {
    $('.singledate td.fc-day-top').removeClass('active'),
    $(this).addClass('active');
    var x = $(this).find('span').text();
    var y = $(this).parents('#calendar1').find('h2').text();
    if (x !== null || x !== '') {
      $('.popnext').removeAttr("disabled");
    }
  var d = document.getElementById('slot_date')
  d.innerHTML = `Selected Date : <span class="dated">${x + ' ' + y} </span>`

  var e = document.getElementById('slot_timing')
  e.innerHTML = `<span class="dated">${x + ' ' + y} </span>`

  var current_selected_date = x + ' ' + y
  sessionStorage.setItem('singleSelectDate', current_selected_date)
  // alert('Current selected date',current_selected_date)
  console.log(sessionStorage.getItem('singleSelectDate'))
});

$(document).on('click', '.singledate td.fc-today', function () {
  $('.singledate td.fc-day-top').removeClass('active'),
  $(this).addClass('active');
  var x = $(this).find('span').text();
  var y = $(this).parents('#calendar1').find('h2').text();
  if (x !== null || x !== '') {
    $('.popnext').removeAttr("disabled");
  }




var d = document.getElementById('slot_date')
d.innerHTML = `Selected Date : <span class="dated">${x + ' ' + y} </span>`

var e = document.getElementById('slot_timing')
e.innerHTML = `<span class="dated">${x + ' ' + y} </span>`

var current_selected_date = x + ' ' + y
sessionStorage.setItem('singleSelectDate', current_selected_date)
// alert('Current selected date',current_selected_date)
console.log(sessionStorage.getItem('singleSelectDate'))
});
var datesArr = []
$(document).on('click', '.multidate td.fc-day-top', function () {
  // $('.multiple td.fc-day-top').removeClass('fc-today'),
  $(this).addClass('fc-today');
  var x = $(this).find('span').text();
  var y = $(this).parents('#calendar1').find('h2').text();
  var d = x + ' ' + y
  if (x !== null || x !== '') {
    $('.popnext').removeAttr("disabled");
  }
  //alert(datesArr.includes(d))
  if (datesArr.includes(d)) {
    var index = datesArr.indexOf(d);
    datesArr.splice(index, 1);
  } else {
    datesArr.push(x + ' ' + y);
  }
  // alert(datesArr)
  sessionStorage.setItem('multiSelectDate', datesArr)
  // alert(x + ' ' + y);
});