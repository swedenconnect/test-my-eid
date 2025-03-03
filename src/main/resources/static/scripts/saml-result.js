jQuery(function ($) {

    $(document).ready(function () {

        $('.drop-down > p').click(function () {
            $(this).parent('.drop-down').toggleClass('open');
        });

        $('.drop-down-container').show();

        // Advanced attributes
        if ($('#advancedAttributes').length > 0) {
            $('#more-attributes-div2').show();
            $('#more-attributes-div').show();
            $('#advancedAttributes').hide();
        }

        $('#more-attributes-div').click(function () {
            $('#more-attributes-div').hide();
            $('#advancedAttributes').show();
        });

    });

});
