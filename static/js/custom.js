$(document).on('click','.eye',function(){
    if($('.eye.eye1').hasClass('showCommon')){
        $('.eye.eye1').removeClass('showCommon');
        $('.eye.eye1 i').removeClass('fa fa-eye-slash').addClass('fa fa-eye');
        $('.passShow').attr('type','text');
    }
    else{
        $('.eye.eye1').addClass('showCommon');
        $('.eye.eye1 i').removeClass('fa fa-eye').addClass('fa fa-eye-slash'); 
          $('.passShow').attr('type','password');
    }
});

$(document).on('click','span.hum',function(){
    $(this).addClass('active');
    $('span.sidecontent').addClass('active');
    $('.commonInner').addClass('active');
    $('.sidenav').addClass('active');
});
$(document).on('click','span.hum.active',function(){
    $(this).removeClass('active');
  
    $('.commonInner').removeClass('active');
    $('.sidenav').removeClass('active');
        $('span.sidecontent').removeClass('active');
});