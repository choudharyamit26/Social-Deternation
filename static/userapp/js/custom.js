$(window).on('scroll',function(){
  if ($(window).scrollTop() >= 78) {
    $('.header').addClass('fixedHeader');
} else {
    $('.header').removeClass('fixedHeader');
}
});

$(document).on('click','.signUpby ul li',function(){
  $('.signUpby ul li').removeClass('active');
  $(this).addClass('active');
});

$(document).on('click','.signUpby ul li.first',function(){
  $('.formByMail').addClass('active');
  $('.formByNumber').removeClass('active');
});
$(document).on('click','.signUpby ul li.second',function(){
  $('.formByNumber').addClass('active');
  $('.formByMail').removeClass('active');
});


$(document).on('click','.solotTome label',function(){
  $(".solotTome label").removeClass('active');
  $(this).addClass('active');
});

$(document).on('click','.video',function(){
  $('.call1').animate({'top':'0'});
  $('.call2').animate({'top':'-100%'});
});
$(document).on('click','.cutcall',function(){
  $('.call1').animate({'top':'-100%'});
  $('.returnCallAudio').slideUp();
});
$(document).on('click','.vidio',function(){
  $('.call2').animate({'top':'0'});
  $('.call1').animate({'top':'-100%'});
});
$(document).on('click','.cutcall',function(){
  $('.call2').animate({'top':'-100%'});
});
$(document).on('click','.welcomeBord a',function(){
  $('.welcomeBord').slideUp();
});
$(document).on('click','.returnCallAudio',function(){
  $('.call1').animate({'top':'0'});
  $('.returnCallAudio').slideUp();
});
$(document).on('click','.message',function(){
   $('.call1').animate({'top':'-100%'});
   $('.returnCallAudio').slideDown();
  // alert('okk');
});
$(document).on('click','.returnCallVideo',function(){
  $('.call2').animate({'top':'0'});
  $('.returnCallVideo').slideUp();
});
$(document).on('click','.message2',function(){
  $('.call2').animate({'top':'-100%'});
  $('.returnCallVideo').slideDown();
 // alert('okk');
});

$(document).on('click','.pagin ul li a',function(){
  $('.pagin ul li a').removeClass('active');
  $(this).addClass('active');
});

$(document).ready(function() {
  var firstSite = sessionStorage['firstSite'];
  if (!firstSite) { // or firstSite != "visited"

      // some code here if the user is new to the site
      $('#firstmodal').modal('show');

      sessionStorage['firstSite'] = "visited";
  }
});
$(document).on('click','.socialRight ul li a',function(){
  $('.socialRight ul li a').removeClass('active');
  $(this).addClass('active');
});

$(document).on('click','.niceCountryInputMenuDropdownContent a',function(){
 $('#stop').modal('show');
 $('#firstmodal').modal('hide');
})

function readURL(input) {
  if (input.files && input.files[0]) {
      var reader = new FileReader();
      reader.onload = function(e) {
          $('#imagePreview').css('background-image', 'url('+e.target.result +')');
          $('#imagePreview').hide();
          $('#imagePreview').fadeIn(650);
      }
      reader.readAsDataURL(input.files[0]);
  }
}
$("#imageUpload").change(function() {
  readURL(this);
});
$(document).on('click','.notification',function(){
  $('.notificationDet').slideDown();
  // alert('okk');
});

document.addEventListener("mousedown", function (event) {
  if (event.target.closest(".notificationDet,.notification"))
      return;
  $('.notificationDet').slideUp();
});

// $(document).on('click','.submitt',function(){
  

//     setTimeout(function(){
//      $('#submitRecord').modal('hide');
//  $('#submitRecord2').modal('show');  
//       }, 3000);

// });


