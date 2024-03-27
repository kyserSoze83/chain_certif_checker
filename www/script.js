var certErr = [];
var certsFiles = [];

function displayFileName() {
    var fileName = $('#input_file').prop('files')[0].name;
    $('#file_name').text(fileName).show();
}

function handle_file_select( evt ) {
    let fl_files = evt.target.files; // JS FileList object

    // use the 1st file from the list
    let fl_file = fl_files[0];

    let reader = new FileReader(); // built in API

    let display_file = ( e ) => { // set the contents of the <textarea>
        certsFiles.push({
            name: fl_file.name,
            content: e.target.result
        });
    };

    let on_reader_load = ( fl ) => {
        return display_file; // a function
    };

    // Closure to capture the file information.
    reader.onload = on_reader_load( fl_file );

    // Read the file as text.
    reader.readAsText( fl_file );
}

document.getElementById( 'input_file' ).addEventListener( 'change', handle_file_select, false );

function sendToServer() {
    $.ajax({
        url: '/valid_cert',
        type: 'POST',
        data: {
            json: JSON.stringify(certsFiles)
        },
        contentType: 'application/json',
        success: function(response){
            var jsonData = JSON.parse(response);

            console.log(jsonData);

            jsonData.forEach(data => {
                if (data.id < 0) {
                    certErr.push(data);
                }else if(data.id == 0){
                    console.log("add certificate")
                    const tabContent = '<div class="resultat" id="restab_' + certsFiles.length + '"><table><thead><tr><th scope="col">Attribut</th><th scope="col">Value</th></tr></thead><tbody class="tbody_values" id="tbody_values_' + certsFiles.length + '"></tbody></table></div>'

                    $('#cert_chain').append(tabContent);
                    $('#tbody_values_' + certsFiles.length).empty();
                    $('#restab_' + certsFiles.length).css('display', 'block');

                    $.each(data, function(key, value) {
                        if (key != 'id' && key != 'format') {
                            $('#tbody_values_' + certsFiles.length).append('<tr><th scope="row">' + key + '</th><td>' + value + '</td></tr>');
                        }
                    });
                }else{
                    if(data.valid == 'True'){
                        document.getElementsByTagName('body')[0].style.backgroundColor = 'green';
                    }else{
                        document.getElementsByTagName('body')[0].style.backgroundColor = 'red';
                    }
                }
            });
        },
        error: function(xhr, status, error){
            console.error(error);
        }
    });
}