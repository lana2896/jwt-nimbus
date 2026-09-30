$(document).ready(function () {
    if ($('#profile').length) {
        var token = localStorage.getItem('token');
        if (!token) {
            window.location.href = '/login';
            return;
        }
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Authorization', 'Bearer ' + token);
            },
            success: function (data) {
                $('#profile').text(data.fullName);
                if (data.images) {
                    $('#images').attr('src', data.images);
                }
            },
            error: function () {
                localStorage.removeItem('token');
                alert('Sorry, you are not logged in.');
                window.location.href = '/login';
            }
        });
    }

    $('#logout').click(function () {
        localStorage.clear();
        window.location.href = '/login';
    });

    $('#loginForm').on('submit', function (e) {
        e.preventDefault();
        var payload = JSON.stringify({
            email: $('#email').val(),
            password: $('#password').val()
        });
        $.ajax({
            type: 'POST',
            url: '/auth/login',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: payload,
            success: function (data) {
                localStorage.setItem('token', data.token);
                window.location.href = '/user/profile';
            },
            error: function () {
                alert('Login Failed');
            }
        });
    });
});
