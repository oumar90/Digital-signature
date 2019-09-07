$.ajax({
  url: "https://phantauth.net/user/",
  dataType: "json",
  success: function(user) {
    new Vue({ el: "#user", data: { user: user } });
    $("#user").show();
  }
});
