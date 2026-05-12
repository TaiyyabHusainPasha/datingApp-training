using System;
using API.Helpers;
using API.interfaces;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.CodeAnalysis.Options;
using Microsoft.Extensions.Options;

namespace API.Services;

public class PhotoService : IPhotoService
{
    private readonly Cloudinary _cloudnary;
    public PhotoService(IOptions<CloudnarySettings> config)
    {
        var account = new Account(
            config.Value.CloudName, 
            config.Value.ApiKey, 
            config.Value.ApiSecret);

        _cloudnary = new Cloudinary(account);
    }
    public async Task<DeletionResult> DeletePhotoAsync(string publicId)
    {
        var deleteParams = new DeletionParams(publicId);
        return await _cloudnary.DestroyAsync(deleteParams);
    }

    public async Task<ImageUploadResult> UploadPhotoAsync(IFormFile file)
    {
        var uploadResult = new ImageUploadResult();
        if(file.Length > 0)
        {
            await using var stream = file.OpenReadStream();
            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(file.FileName, stream),
                Transformation = new Transformation().Height(500).Width(500).Crop("fill").Gravity("face"),
                Folder = "da-ang20"
            };
            uploadResult = await _cloudnary.UploadAsync(uploadParams);
        }
        return uploadResult;
    }
}
