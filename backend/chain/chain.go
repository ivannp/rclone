package chain

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	gohash "hash"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fspath"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fs/operations"
	"google.golang.org/protobuf/proto"
)

// Globals
// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "chain",
		Description: "Encode (encrypt and/or compress) a remote",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "remote",
			Help:     "Remote to encode.\nNormally should contain a ':' and a path, e.g. \"myremote:path/to/dir\",\n\"myremote:bucket\" or maybe \"myremote:\" (not recommended).",
			Required: true,
		}, {
			Name:     "compression",
			Help:     "Compression algorithm.",
			Default:  "zstd",
			Advanced: true,
		}, {
			Name:     "encryption",
			Help:     "Encryption algorithm chain.",
			Default:  "",
			Advanced: true,
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	Remote      string `config:"remote"`
	Compression string `config:"compression"`
	Encryption  string `config:"encryption"`
}

// Fs represents a wrapped fs.Fs
type Fs struct {
	fs.Fs
	wrapper  fs.Fs
	name     string
	root     string
	opt      Options
	features *fs.Features // optional features
}

const (
	defaultIvLength = 16
)

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	remote := opt.Remote
	if strings.HasPrefix(remote, name+":") {
		return nil, errors.New("can't point remote at itself - check the value of the remote setting")
	}

	wInfo, wName, wPath, wConfig, err := fs.ConfigFs(remote)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse remote %q to wrap", remote)
	}

	// Strip trailing slashes if they exist in rpath
	rpath = strings.TrimRight(rpath, "\\/")

	// First, check for a file
	// If a metadata file was found, return an error. Otherwise, check for a directory
	remotePath := fspath.JoinRootPath(wPath, rpath)
	wrappedFs, err := wInfo.NewFs(ctx, wName, remotePath, wConfig)
	if err != fs.ErrorIsFile {
		remotePath = fspath.JoinRootPath(wPath, rpath)
		wrappedFs, err = wInfo.NewFs(ctx, wName, remotePath, wConfig)
	}
	if err != nil && err != fs.ErrorIsFile {
		return nil, errors.Wrapf(err, "failed to make remote %s:%q to wrap", wName, remotePath)
	}

	// Create the wrapping fs
	f := &Fs{
		Fs:   wrappedFs,
		name: name,
		root: rpath,
		opt:  *opt,
	}
	// the features here are ones we could support, and they are
	// ANDed with the ones from wrappedFs
	f.features = (&fs.Features{
		CaseInsensitive:         true,
		DuplicateFiles:          false,
		ReadMimeType:            false,
		WriteMimeType:           false,
		GetTier:                 true,
		SetTier:                 true,
		BucketBased:             true,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f).Mask(ctx, wrappedFs).WrapsFs(f, wrappedFs)
	// We support reading MIME types no matter the wrapped fs
	f.features.ReadMimeType = true
	// We can only support putstream if we have serverside copy or move
	if !operations.CanServerSideMove(wrappedFs) {
		f.features.Disable("PutStream")
	}

	return f, err
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// String returns a description of the FS
func (f *Fs) String() string {
	return fmt.Sprintf("Encrypted drive '%s:%s'", f.name, f.root)
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	return f.Fs.List(ctx, dir)
}

// ListR lists the objects and directories of the Fs starting
// from dir recursively into out.
//
// dir should be "" to start from the root, and should not
// have trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
//
// It should call callback for each tranche of entries read.
// These need not be returned in any particular order.  If
// callback returns an error then the listing will stop
// immediately.
//
// Don't implement this unless you have a more efficient way
// of listing recursively that doing a directory traversal.
func (f *Fs) ListR(ctx context.Context, dir string, callback fs.ListRCallback) (err error) {
	return f.Fs.Features().ListR(ctx, dir, callback)
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	o, err := f.Fs.NewObject(ctx, remote)
	if err != nil {
		return nil, err
	}
	return f.newObjectWithoutMeta(o, -1), nil
}

func (f *Fs) buildFileHeader() (*FileHeader, error) {
	var ans = &FileHeader{}
	ans.Encoders = strings.Split(f.opt.Encryption, ",")

	ans.Ivs = make([][]byte, len(ans.Encoders))
	for i := 0; i < len(ans.Encoders); i++ {
		ans.Ivs[i] = make([]byte, defaultIvLength)
		rand.Read(ans.Ivs[i])
	}

	ans.Compression = f.opt.Compression
	return ans, nil
}

func writeFileHeader(w io.Writer, fh *FileHeader) error {
	headerBuffer, err := proto.Marshal(fh)
	if err != nil {
		return err
	}

	// Write out the header length
	var headerLen int32 = int32(len(headerBuffer))

	err = binary.Write(w, binary.LittleEndian, headerLen)
	if err != nil {
		return err
	}

	// Write out the serialized header
	n, err := w.Write(headerBuffer)
	if err != nil {
		return err
	}

	if n != len(headerBuffer) {
		return errors.New("Writing failed [tried ]" + string(len(headerBuffer)) + " bytes, wrote " + string(n) + " bytes].")
	}
	return err
}

type EncodedFile struct {
	file        *os.File
	md5         string // File hash
	size        int64  // The compressed size
	compression string // the compression method (zstd, zlib, ...)
}

// The encoded (after compression and encryption) file size
func (ef *EncodedFile) Size() int64 {
	st, err := ef.file.Stat()
	if err != nil {
		return -1
	}
	return st.Size()
}

func NewEncodedFile() *EncodedFile {
	tf, err := ioutil.TempFile("", "rclone-encode-")
	if err != nil {
		return nil
	}
	return &EncodedFile{tf, "", -1, "none"}
}

func (ef *EncodedFile) Writer() io.Writer {
	return ef.file
}

func (ef *EncodedFile) Name() string {
	return ef.file.Name()
}

func (ef *EncodedFile) Seek(offset int64, whence int) (int64, error) {
	if ef.file == nil {
		return -1, errors.New("Bad encoded file object")
	}
	ans, err := ef.file.Seek(offset, whence)
	if err != nil {
		return -1, err
	}
	return ans, nil
}

func (ef *EncodedFile) Close() {
	if ef.file != nil {
		ef.file.Close()
		os.Remove(ef.file.Name())
		ef.file = nil
	}
}

func (f *Fs) encodeFile(in io.Reader) (*EncodedFile, error) {
	var ans = NewEncodedFile()
	if ans == nil {
		return nil, errors.New("Failed to create a temp file for encoding")
	}

	// Build the file header from the current config
	fh, err := f.buildFileHeader()
	if err != nil {
		return ans, err
	}

	// Write the file header
	err = writeFileHeader(ans.Writer(), fh)
	if err != nil {
		return ans, err
	}

	var topWriter io.Writer = ans.Writer()

	var zstdWriter *zstd.Encoder

	var compressionWriter io.Writer

	switch fh.Compression {
	case "zstd":
		zstdWriter, err = zstd.NewWriter(topWriter)
		if err != nil {
			return ans, err
		}
		compressionWriter = zstdWriter
		defer zstdWriter.Close()

		topWriter = compressionWriter
	}

	var hashWriter = md5.New()
	topWriter = io.MultiWriter(hashWriter, topWriter)

	_, err = io.Copy(topWriter, in)
	if err != nil {
		return ans, err
	}

	ans.md5 = hex.EncodeToString(hashWriter.Sum(nil))

	return ans, nil
}

// put implements Put or PutStream
func (f *Fs) put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options []fs.OpenOption) (fs.Object, error) {
	// Encode the file to a temp location
	encodedFile, err := f.encodeFile(in)
	if encodedFile != nil {
		defer encodedFile.Close()
	}
	if err != nil {
		return nil, err
	}

	// TODO Store the actual files size and the hash in the file's extended attributes

	var info = object.NewStaticObjectInfo(src.Remote(), src.ModTime(ctx), src.Size(), false, map[hash.Type]string{hash.MD5: encodedFile.md5}, f.Fs)

	// Seek to the start of the encoded file
	encodedFile.Seek(0, 0)

	o, err := f.Fs.Put(ctx, encodedFile.file, info, options...)
	if err != nil {
		return nil, err
	}

	meta := newMeta(src.Size(), "", f.opt.Compression)

	return f.newObject(o, meta), nil
}

// Put in to the remote path
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// If there's already an existent objects we need to make sure to explicitly update it to make sure we don't leave
	// orphaned data. Alternatively we could also deleted (which would simpler) but has the disadvantage that it
	// destroys all server-side versioning.
	o, err := f.NewObject(ctx, src.Remote())
	if err == fs.ErrorObjectNotFound {
		// Get our file compressibility
		return f.put(ctx, in, src, options)
	}
	if err != nil {
		return nil, err
	}
	return o, o.Update(ctx, in, src, options...)
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.put(ctx, in, src, options)
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.MD5)
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.Fs.Mkdir(ctx, dir)
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.Fs.Rmdir(ctx, dir)
}

// Purge all files in the directory specified
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context, dir string) error {
	do := f.Fs.Features().Purge
	if do == nil {
		return fs.ErrorCantPurge
	}
	return do(ctx, dir)
}

// Copy src to this remote using server-side copy operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	do := f.Fs.Features().Copy
	if do == nil {
		return nil, fs.ErrorCantCopy
	}
	o, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}
	oResult, err := do(ctx, o.Object, remote)
	if err != nil {
		return nil, err
	}
	return f.newObjectWithoutMeta(oResult, src.Size()), nil
}

// Move src to this remote using server-side move operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	do := f.Fs.Features().Move
	if do == nil {
		return nil, fs.ErrorCantMove
	}
	o, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}
	oResult, err := do(ctx, o.Object, remote)
	if err != nil {
		return nil, err
	}
	return f.newObjectWithoutMeta(oResult, src.Size()), nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	do := f.Fs.Features().DirMove
	if do == nil {
		return fs.ErrorCantDirMove
	}
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(srcFs, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}
	return do(ctx, srcFs.Fs, srcRemote, dstRemote)
}

// openFile represents an Object open for reading
type openFile struct {
	o       *Object       // Object we are reading for
	wrapped io.ReadCloser // The wrapped reader
	reader  io.Reader     // Read from here
	hash    gohash.Hash   // currently accumulating SHA1
	bytes   int64         // number of bytes read on this connection
	eof     bool          // whether we have read end of file
}

// newOpenFile wraps an io.ReadCloser and checks the sha1sum
func newOpenFile(o *Object, reader io.ReadCloser, fh *FileHeader) (*openFile, error) {
	var zstdReader *zstd.Decoder
	var topReader io.Reader = reader
	var err error

	switch fh.Compression {
	case "zstd":
		zstdReader, err = zstd.NewReader(reader)
		if err != nil {
			return nil, err
		}
		topReader = zstdReader
	}

	ans := &openFile{o: o, wrapped: reader, hash: md5.New()}
	ans.reader = io.TeeReader(topReader, ans.hash)

	return ans, nil
}

// Read bytes from the object - see io.Reader
func (file *openFile) Read(p []byte) (n int, err error) {
	n, err = file.reader.Read(p)
	file.bytes += int64(n)
	println("Read ", n, "bytes, ", len(p), " requested.")
	if err == io.EOF {
		file.eof = true
	}
	return
}

// Close the object and checks the length and SHA1 if all the object
// was read
func (file *openFile) Close() (err error) {
	defer fs.CheckClose(file.wrapped, &err)

	// If not end of file then can't check SHA1
	if !file.eof {
		return nil
	}

	// TODO Verify the original size
	// TODO Verify the MD5

	return nil
}

// Check it satisfies the interfaces
var _ io.ReadCloser = &openFile{}

// Open opens the file for read.  Call Close() on the returned io.ReadCloser. Note that this call requires quite a bit of overhead.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (rc io.ReadCloser, err error) {
	reader, err := o.Object.Open(ctx, options...)
	if err != nil {
		return nil, err
	}

	// Read the header length
	var headerLen int32
	err = binary.Read(reader, binary.LittleEndian, &headerLen)
	if err != nil {
		return nil, err
	}

	// Read the header content
	headerBuffer := make([]byte, headerLen)
	nn, err := reader.Read(headerBuffer)
	if err != nil {
		return nil, err
	}

	if nn != len(headerBuffer) {
		return nil, errors.New("Reading failed [tried ]" + string(headerLen) + " bytes, read " + string(nn) + " bytes].")
	}

	header := new(FileHeader)
	err = proto.Unmarshal(headerBuffer, header)
	if err != nil {
		return nil, err
	}

	return newOpenFile(o, reader, header)
}

// CleanUp the trash in the Fs
//
// Implement this if you have a way of emptying the trash or
// otherwise cleaning up old versions of files.
func (f *Fs) CleanUp(ctx context.Context) error {
	do := f.Fs.Features().CleanUp
	if do == nil {
		return errors.New("can't CleanUp")
	}
	return do(ctx)
}

// About gets quota information from the Fs
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	do := f.Fs.Features().About
	if do == nil {
		return nil, errors.New("About not supported")
	}
	return do(ctx)
}

// UnWrap returns the Fs that this Fs is wrapping
func (f *Fs) UnWrap() fs.Fs {
	return f.Fs
}

// WrapFs returns the Fs that is wrapping this Fs
func (f *Fs) WrapFs() fs.Fs {
	return f.wrapper
}

// SetWrapper sets the Fs that is wrapping this Fs
func (f *Fs) SetWrapper(wrapper fs.Fs) {
	f.wrapper = wrapper
}

// DirCacheFlush resets the directory cache - used in testing
// as an optional interface
func (f *Fs) DirCacheFlush() {
	do := f.Fs.Features().DirCacheFlush
	if do != nil {
		do()
	}
}

// ObjectMeta describes the metadata for an Object.
type ObjectMeta struct {
	Size        int64  // Size of the object.
	MD5         string // MD5 hash of the file.
	Compression string // The compression algorithm
}

// This function generates a metadata object
func newMeta(size int64, md5 string, compression string) *ObjectMeta {
	meta := new(ObjectMeta)
	meta.Size = size
	meta.Compression = compression
	meta.MD5 = md5
	return meta
}

// Object describes a wrapped for being read from the Fs
//
// This decrypts the remote name and decrypts the data
type Object struct {
	fs.Object
	f    *Fs
	size int64
	meta *ObjectMeta
}

func (f *Fs) newObject(o fs.Object, meta *ObjectMeta) *Object {
	return &Object{
		Object: o,
		f:      f,
		size:   meta.Size,
		meta:   meta,
	}
}

func (f *Fs) newObjectWithoutMeta(o fs.Object, size int64) *Object {
	return &Object{
		Object: o,
		f:      f,
		size:   size,
		meta:   nil,
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *Object) Fs() fs.Info {
	return o.f
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.Remote()
}

// Size returns the size of the file
func (o *Object) Size() int64 {
	return o.size
}

// Hash returns the selected checksum of the file
// If no checksum is available it returns ""
func (o *Object) Hash(ctx context.Context, ht hash.Type) (string, error) {
	return o.meta.MD5, nil
}

// UnWrap returns the wrapped Object
func (o *Object) UnWrap() fs.Object {
	return o.Object
}

// Update in to the object with the modTime given of the given size
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	_, err := o.f.put(ctx, in, src, options)
	return err
}

// UserInfo returns info about the connected user
func (f *Fs) UserInfo(ctx context.Context) (map[string]string, error) {
	do := f.Fs.Features().UserInfo
	if do == nil {
		return nil, fs.ErrorNotImplemented
	}
	return do(ctx)
}

// Disconnect the current user
func (f *Fs) Disconnect(ctx context.Context) error {
	do := f.Fs.Features().Disconnect
	if do == nil {
		return fs.ErrorNotImplemented
	}
	return do(ctx)
}

// Shutdown the backend, closing any background tasks and any
// cached connections.
func (f *Fs) Shutdown(ctx context.Context) error {
	do := f.Fs.Features().Shutdown
	if do == nil {
		return nil
	}
	return do(ctx)
}

// ObjectInfo describes a wrapped fs.ObjectInfo for being the source
//
// This encrypts the remote name and adjusts the size
type ObjectInfo struct {
	fs.ObjectInfo
	f     *Fs
	nonce nonce
}

func (f *Fs) newObjectInfo(src fs.ObjectInfo, nonce nonce) *ObjectInfo {
	return &ObjectInfo{
		ObjectInfo: src,
		f:          f,
		nonce:      nonce,
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *ObjectInfo) Fs() fs.Info {
	return o.f
}

// Remote returns the remote path
func (o *ObjectInfo) Remote() string {
	return o.ObjectInfo.Remote()
}

// Size returns the size of the file
func (o *ObjectInfo) Size() int64 {
	size := o.ObjectInfo.Size()
	return size
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	do, ok := o.Object.(fs.IDer)
	if !ok {
		return ""
	}
	return do.ID()
}

// SetTier performs changing storage tier of the Object if
// multiple storage classes supported
func (o *Object) SetTier(tier string) error {
	do, ok := o.Object.(fs.SetTierer)
	if !ok {
		return errors.New("crypt: underlying remote does not support SetTier")
	}
	return do.SetTier(tier)
}

// GetTier returns storage tier or class of the Object
func (o *Object) GetTier() string {
	do, ok := o.Object.(fs.GetTierer)
	if !ok {
		return ""
	}
	return do.GetTier()
}

// Check the interfaces are satisfied
var (
	_ fs.Fs          = (*Fs)(nil)
	_ fs.Purger      = (*Fs)(nil)
	_ fs.Copier      = (*Fs)(nil)
	_ fs.Mover       = (*Fs)(nil)
	_ fs.PutStreamer = (*Fs)(nil)
	_ fs.CleanUpper  = (*Fs)(nil)
	_ fs.ListRer     = (*Fs)(nil)
	_ fs.ObjectInfo  = (*ObjectInfo)(nil)
	_ fs.Object      = (*Object)(nil)
	_ fs.IDer        = (*Object)(nil)
)
