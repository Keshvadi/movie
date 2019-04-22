
/*
 * Editor client script for DB table stonefinderstones
 * Created by http://editor.datatables.net/generator
 */

(function($){

$(document).ready(function() {
	var table = $('#stonefinderstones').DataTable( {
		serverSide: true,
		fixedHeader: true,
		ajax: {
        url: 'php/table.stonefinderstones.php',
        type: "POST"
        },
		columnDefs: [
		{ orderable: true, targets: '_all'},
		{ targets: 8, render: function (data, type, row, meta) {return (data == null) ? "" : "£" + data;} },
		{ targets: 9, data: 'url', render: function ( data, type, row, meta ) {return '<a href="https://www.wardgemstones.com/'+data+'"><h6 style="text-align:center;font-size:110%;font-weight:bold;">View</h6></a>';}},
		{ targets: 2, data: 'thumbnail', render: function ( data, type, row, meta ) {return (data == "") ? '<img style="width:50px;height:50px;display:block;margin:0 auto;" src="https://www.wardgemstones.com/stonefinder/awaiting-image.png">' : '<img style="width:50px;height:50px;display:block;margin:0 auto;" src="https://www.wardgemstones.com/media/catalog/product'+data+'">';}}
		],
		
		
		columns: [
			{
				"data": "sku"
			},
			{
				"data": "status",
				visible: false
			},
			{
				"data": "thumbnail",
				orderable: false,
				"defaultContent": ""
			},
			{
				"data": "name",
				orderable: false
			},
			{
				"data": "category",
				searchable: true
			},
			{
				"data": "material",
				searchable: true
			},
			{
				"data": "shape",
				searchable: true
			},
			{
				"data": "size",
				orderable: false,
				searchable: true
			},
			{
				"data": "price"
			},
			{
				"data": "url",
				orderable: false
			}
		],
		language: {
        search: "_INPUT_",
		processing: '<h6 style="font-weight:bold;color:#000099;">Fetching the Stones...</h6>',
		searchPlaceholder: "Search",
		zeroRecords: "<h4>Not seeing the stones you want?  Did you reset the grid before searching?</h4><p>If you still can't see what you want, please call on 020 72534036 or email us orders@aewgems.co.uk"
		},
		select: false,
		lengthChange: false,
		processing: true,
		deferRender: true,
		order: [[ 0, 'asc' ]],
		stateSave: true,
		lengthMenu: [ [10, 25, 50, 200, 500, 1000], [10, 25, 50, 200, 500, 1000] ],
		scrollX: false,
		scrollY: '72vh',
		paging: true,
		pageLength: 100,
	} );
	
	// Search by Size Text Input
$('#sizetext').on( 'keyup', function () {
    table
        .columns( 7 )
        .search( this.value )
        .draw();
} );
	
	// Destroy State Save and re-draw
$('#destroy').click(function () {
  table.state.clear();
window.location.reload();
 });
 
 // Category Search-full search
$('#category').on( 'change', function () {
    table
        .columns( 4 )
        .search( this.value )
        .draw();
} );
// Material Search-full search
$('#material').on( 'change', function () {
    table
        .columns( 5 )
        .search( this.value )
        .draw();
} );

// Shape Search -full search
$('#shape').on( 'change', function () {
    table
        .columns( 6 )
        .search( this.value )
        .draw();
} );
		
	// Buttons Function
new $.fn.dataTable.Buttons(table, [
  "excelHtml5",
  "copy",
  "print",
  "colvis",
  "pageLength"
]);
 
table
  .buttons()
  .container()
  .appendTo($('#buttons'));
	
$('div.dataTables_filter').appendTo($('#globalsearch'));	
		
} );
/////End of Buttons	

}(jQuery));

